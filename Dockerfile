From openjdk:17
WORKDIR /usr/app
COPY src/main/resources src/main/resources
COPY ./build/libs/*.jar webfluxblog-authorization-server.jar
CMD ["java","-jar","webfluxblog-authorization-server.jar"]