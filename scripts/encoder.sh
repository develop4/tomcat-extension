#!/bin/sh


JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.7.0_45.jdk/Contents/Home
TOMCAT_HOME=/data/narowner/product/apache/apache-tomcat-7.0.54

PATH=${JAVA_HOME}/bin:${PATH}

SCRIPT_NAME=encoder.sh
BIN_DIR=`dirname $0`
DIST_DIR=$BIN_DIR/..
LIB_DIR=$DIST_DIR/lib
TARGET_DIR=$DIST_DIR/target
EXEC_CLASSPATH="."
SEPERATOR=":"

PWD=`pwd`
CATALINA_BASE=`dirname $PWD`

for a in `find $LIB_DIR -name '*.jar'`
do
  EXEC_CLASSPATH=${EXEC_CLASSPATH}${SEPERATOR}${a}
done

for a in `find $TOMCAT_HOME -name '*.jar'`
do
  EXEC_CLASSPATH=${EXEC_CLASSPATH}${SEPERATOR}${a}
done

JAVA_EXECUTABLE=java
if [ -n "$JAVA_HOME" ]
then
  JAVA_EXECUTABLE=$JAVA_HOME/bin/java
fi

export CATALINA_BASE

echo ============================
echo CATALINA_BASE:   $CATALINA_BASE

$JAVA_EXECUTABLE -Dcatalina.base=$CATALINA_BASE -classpath ${TARGET_DIR}/tomcat-extension-0.2.0.jar${SEPERATOR}$EXEC_CLASSPATH uk.co.develop4.security.tomcatutils.cli.DecoderCli $*