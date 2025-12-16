FROM node:20-alpine
WORKDIR /app
RUN npm install -g http-server
COPY . .
EXPOSE 3000
CMD ["http-server", ".", "-p", "3000"]

