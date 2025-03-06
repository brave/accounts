package datastore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/brave/accounts/util"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// Verification represents an email verification record and its status
type Verification struct {
	// ID uniquely identifies the verification request
	ID uuid.UUID
	// Email stores the address to be verified
	Email string
	// Code contains the verification code sent to the user
	Code string
	// Verified indicates whether the email has been successfully verified
	Verified bool
	// Service identifies the actor that initiated the verification
	Service string
	// Intent describes the purpose of the verification
	Intent string
	// CreatedAt records when the verification was initiated
	CreatedAt time.Time `gorm:"<-:update"`
}

const (
	AuthTokenIntent    = "auth_token"
	VerificationIntent = "verification"
	RegistrationIntent = "registration"
	SetPasswordIntent  = "set_password"

	codeLength              = 32
	verifyWaitMaxDuration   = 20 * time.Second
	VerificationExpiration  = 30 * time.Minute
	maxPendingVerifications = 3

	verificationChannelName = "verification"
)

type verificationWaitRequest struct {
	responseChan chan<- bool
	startTime    time.Time
}

// CreateVerification creates a new verification record
func (d *Datastore) CreateVerification(email string, service string, intent string) (*Verification, error) {
	code := util.GenerateRandomString(codeLength)

	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	email = util.CanonicalizeEmail(email)
	verification := Verification{
		ID:       id,
		Email:    email,
		Code:     code,
		Service:  service,
		Intent:   intent,
		Verified: false,
	}

	var existingCount int64
	if err := d.DB.Model(&Verification{}).
		Where("email = ? AND verified = false AND created_at > ?",
			email,
			time.Now().Add(-VerificationExpiration)).
		Count(&existingCount).Error; err != nil {
		return nil, fmt.Errorf("error counting verifications: %w", err)
	}

	if existingCount >= maxPendingVerifications {
		return nil, util.ErrTooManyVerifications
	}
	if err := d.DB.Create(&verification).Error; err != nil {
		return nil, fmt.Errorf("error creating verification: %w", err)
	}

	return &verification, nil
}

// UpdateVerificationStatus updates the verification status for a given email
func (d *Datastore) UpdateAndGetVerificationStatus(id uuid.UUID, code string) (*Verification, error) {
	result := d.DB.Model(&Verification{}).
		Where("id = ? AND code = ? AND verified = false", id, code).
		Update("verified", true)

	if result.Error != nil {
		return nil, fmt.Errorf("error updating verification status: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return nil, util.ErrVerificationNotFound
	}

	// Send notification
	if err := d.DB.Exec(
		"SELECT pg_notify(?, ?)",
		verificationChannelName,
		id.String(),
	).Error; err != nil {
		return nil, fmt.Errorf("failed to send notification: %w", err)
	}

	return d.GetVerificationStatus(id)
}

// GetVerificationStatus checks if email is verified with given token
func (d *Datastore) GetVerificationStatus(id uuid.UUID) (*Verification, error) {
	var verification Verification
	if err := d.DB.First(&verification, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, util.ErrVerificationNotFound
		}
		return nil, fmt.Errorf("error fetching verification: %w", err)
	}

	if time.Since(verification.CreatedAt) > VerificationExpiration {
		if err := d.DB.Delete(&verification).Error; err != nil {
			return nil, fmt.Errorf("error deleting expired verification: %w", err)
		}
		return nil, util.ErrVerificationNotFound
	}

	return &verification, nil
}

// Authenticates id and code with pending verification, and returns true if verification is still pending
func (d *Datastore) EnsureVerificationCodeIsPending(id uuid.UUID, code string) error {
	verification, err := d.GetVerificationStatus(id)
	if err != nil {
		return err
	}

	if verification.Code != code || verification.Verified {
		return util.ErrVerificationNotFound
	}

	return nil
}

func (d *Datastore) WaitOnVerification(ctx context.Context, id uuid.UUID) (bool, error) {
	waitChan := make(chan bool)

	d.verificationEventWaitMapLock.Lock()
	d.verificationEventWaitMap[id] = &verificationWaitRequest{
		responseChan: waitChan,
		startTime:    time.Now(),
	}
	d.verificationEventWaitMapLock.Unlock()

	// Check the database to see if the verification status changed
	// while setting up the listener.
	var verification Verification
	result := d.DB.Select("verified").Where("id = ?", id).First(&verification)
	if result.Error != nil {
		return false, result.Error
	}
	if verification.Verified {
		return true, nil
	}

	select {
	case verified := <-waitChan:
		return verified, nil
	case <-time.After(verifyWaitMaxDuration):
		return false, nil
	}
}

func (d *Datastore) StartVerificationEventListener() {
	d.verificationEventWaitMap = make(map[uuid.UUID]*verificationWaitRequest)
	go func() {
		for {
			ctx := context.Background()
			conn, err := d.listenPool.Acquire(ctx)
			if err != nil {
				log.Panic().Err(err).Msg("failed to acquire database conn from pool")
			}

			err = util.ListenOnPGChannel(ctx, conn, verificationChannelName)
			if err != nil {
				log.Panic().Err(err).Msg("failed to listen on channel")
			}

			for {
				notif, err := conn.Conn().WaitForNotification(ctx)
				if err != nil {
					log.Error().Err(err).Msg("error waiting for notification")
					conn.Release()
					break
				}
				verificationID, err := uuid.Parse(notif.Payload)
				if err != nil {
					log.Error().Err(err).Msg("invalid verification ID while listening")
					continue
				}
				d.verificationEventWaitMapLock.Lock()
				if request, ok := d.verificationEventWaitMap[verificationID]; ok {
					select {
					case request.responseChan <- true:
						// Successfully sent the verification status
					default:
						// Channel is closed, skip sending
					}
					delete(d.verificationEventWaitMap, verificationID)
				}
				d.verificationEventWaitMapLock.Unlock()
			}
		}
	}()
	go func() {
		for {
			d.verificationEventWaitMapLock.Lock()
			for verificationID, req := range d.verificationEventWaitMap {
				if time.Since(req.startTime) >= verifyWaitMaxDuration {
					delete(d.verificationEventWaitMap, verificationID)
				}
			}
			d.verificationEventWaitMapLock.Unlock()

			time.Sleep(time.Second * 30)
		}
	}()
}

func (d *Datastore) DeleteVerification(id uuid.UUID) error {
	result := d.DB.Delete(&Verification{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete verification: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return util.ErrVerificationNotFound
	}

	return nil
}
