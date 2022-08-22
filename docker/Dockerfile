# Use the official Python image from the Docker Hub
FROM python:3.8.2

# These two environment variables prevent __pycache__/ files.
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1


RUN apt-get update \
    && apt-get install -y netcat

RUN apt-get install -y clamav
RUN apt-get install -y clamdscan
COPY clamd.conf /etc/clamav

# Create an app user in the app group. 
RUN useradd --user-group --create-home --no-log-init --shell /bin/bash app

ENV APP_HOME=/home/app/web

# Create the staticfiles directory. This avoids permission errors. 
RUN mkdir -p $APP_HOME/staticfiles

# Change the workdir.
WORKDIR $APP_HOME

USER app
RUN pip install volatility3
USER root
COPY requirements.txt $APP_HOME
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
COPY . $APP_HOME

RUN chown -R app:app $APP_HOME
RUN /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
RUN /home/linuxbrew/.linuxbrew/bin/brew install bulk_extractor
USER app
RUN export PATH="/home/linuxbrew/.linuxbrew/bin:$PATH"
ENTRYPOINT ["/home/app/web/entrypoint.sh"]
