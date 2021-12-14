FROM gradle:7.3.1-jdk17-alpine AS builder
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle bootJar --no-daemon


FROM openjdk:8u181-jdk-alpine
EXPOSE 8080
RUN mkdir /app
COPY --from=builder /home/gradle/src/build/libs/*.jar /app/spring-boot-application.jar
CMD ["java", "-jar", "/app/spring-boot-application.jar"]

# ADD APPLICATION SECURITY. Overrides CMD specified above.
ADD https://files.trendmicro.com/products/CloudOne/ApplicationSecurity/1.0.2/agent-java/trend_app_protect-4.4.6.jar /app
# Latest version of musl required to work around linking error
RUN apk add --no-cache musl\>1.1.20 --repository http://dl-cdn.alpinelinux.org/alpine/edge/main
ENV TREND_AP_LOG_FILE=STDERR
ENV TREND_AP_KEY=YOUR-KEY-HERE
ENV TREND_AP_SECRET=YOUR-SECRET-HERE
CMD ["java", "-javaagent:/app/trend_app_protect-4.4.6.jar", "-jar", "/app/spring-boot-application.jar"]
