FROM public.ecr.aws/docker/library/postgres:17

RUN apt-get update && apt-get install -y postgresql-17-cron
