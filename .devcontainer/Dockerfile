FROM ubuntu:20.04
RUN apt update && apt upgrade

ARG USERNAME=dev-user
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    #
    # [Optional] Add sudo support. Omit if you don't need to install software after connecting.
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
# ********************************************************
# * Anything else you want to do like clean up goes here *
# ********************************************************
    && apt-get install -y vim \
    && apt-get install -y language-pack-ja-base language-pack-ja \
    && apt-get install -y build-essential \
    && apt-get install -y git \
    && apt-get install -y iproute2 \
    && apt-get install -y iputils-ping \
    && apt-get install -y netcat-openbsd

# [Optional] Set the default user. Omit if you want to keep the default as root.
USER $USERNAME

ENV USER=$USERNAME