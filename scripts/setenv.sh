#!/bin/bash

CATALINA_BASE=/data/develop4/data/DEV001/tomcat/srv01
CATALINA_HOME=/data/develop4/product/apache/apache-tomcat-7.0.54
JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.8.0_121.jdk/Contents/Home

export  JAVA_HOME CATALINA_BASE CATALINA_HOME

EXEC_CLASSPATH=../target/tomcat-extension-0.5.1-SNAPSHOT.jar
export EXEC_CLASSPATH