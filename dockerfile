FROM node:20
WORKDIR /DeliverEase
COPY package.json .
RUN npm install
COPY  . .
EXPOSE 5000
CMD [ "node" , "app" ]