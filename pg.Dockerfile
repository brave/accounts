FROM public.ecr.aws/docker/library/postgres:17

RUN apt update && apt install -y git make gcc postgresql-server-dev-17

RUN git clone https://github.com/citusdata/pg_cron
RUN cd pg_cron && make && make install
