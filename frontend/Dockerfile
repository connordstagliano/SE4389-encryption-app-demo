# syntax=docker/dockerfile:1

FROM node:24-alpine

WORKDIR /app

COPY package.json ./

RUN npm install

COPY . .

CMD ["npm", "run", "dev"]