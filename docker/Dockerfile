# Use the official Python image from the Docker Hub
FROM python:3.8.2

# These two environment variables prevent __pycache__/ files.
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

RUN dpkg --add-architecture i386
RUN apt-get update \
    && apt-get install -y netcat \
    flex \
    libc6:i386 \
    libstdc++6:i386

# Create an app user in the app group. 
RUN useradd --user-group --create-home --no-log-init --shell /bin/bash app

ENV APP_HOME=/home/app/web
ENV LD_LIBRARY_PATH=/home/app/web/bulk


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

# RUN /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

RUN chown -R app:app $APP_HOME
# RUN chown -R app:app /home/linuxbrew
USER app

#Install Bulk Extractor
# RUN echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> /home/app/.profile
# RUN eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
# RUN /home/linuxbrew/.linuxbrew/bin/brew install --build-from-source bulk_extractor; exit 0

ENTRYPOINT ["/home/app/web/entrypoint.sh"]
