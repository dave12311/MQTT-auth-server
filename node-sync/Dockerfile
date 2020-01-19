FROM node:alpine

WORKDIR /usr/src/mqtt-auth

COPY package*.json ./

RUN npm install

RUN npm install -g nodemon

ENTRYPOINT ["nodemon", "./src/sync.js"]