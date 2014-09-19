#Set the base image to debian
FROM debian
RUN apt-get -y update
RUN apt-get -y install wget zip unzip
RUN apt-get -y install git
RUN apt-get -y install gcc automake libtool
RUN apt-get -y install ruby
RUN apt-get -y install ruby-dev
RUN apt-get -y install rubygems
RUN gem install -y fpm
RUN mkdir /root/.ssh/

#copy over private key and set permissions
ADD remote-agent /root/.ssh/remote-agent
RUN chmod 600 /root/.ssh/remote-agent

#create known hosts
RUN touch /root/.ssh/known_hosts
#add key
RUN ssh-keyscan github.com >> /root/.ssh/known_hosts
