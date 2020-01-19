FROM node:alpine

WORKDIR /usr/src/mqtt-auth

COPY package*.json ./

RUN npm install

RUN npm install -g nodemon

EXPOSE 3000

ENTRYPOINT ["nodemon", "./src/auth.js"]