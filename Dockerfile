# Use an official Node.js runtime as a parent image
FROM node:20

# Set the working directory
WORKDIR /usr/app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Expose the application port
EXPOSE 3043

# Start the application
CMD ["npm","run", "start"] 
