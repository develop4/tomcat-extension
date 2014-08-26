#!/bin/sh

PWD=`pwd`
CATALINA_BASE=`dirname $PWD`

PRG="$0"
while [ -h "$PRG" ] ; do
  ls=`ls -ld "$PRG"`
  link=`expr "$ls" : '.*-> \(.*\)$'`
  if expr "$link" : '.*/.*' > /dev/null; then
    PRG="$link"
  else
    PRG=`dirname "$PRG"`/"$link"
  fi
done
PRGDIR=`dirname "$PRG"`

. ${PRGDIR}/setenv.sh

for a in `find $CATALINA_HOME -name '*.jar'`
do
  EXEC_CLASSPATH=${EXEC_CLASSPATH}:${a}
done

JAVA_EXECUTABLE=java
if [ -n "$JAVA_HOME" ]
then
  JAVA_EXECUTABLE=$JAVA_HOME/bin/java
fi

DECODER_PROPERTIES=file:///${CATALINA_BASE}/restricted/settings/decoder.properties

echo ===========================================
echo "CATALINA_BASE:      $CATALINA_BASE"
echo "CATALINA_HOME:      $CATALINA_HOME"
echo "DECODER_PROPERTIES: $DECODER_PROPERTIES"

$JAVA_EXECUTABLE -Dcatalina.base=$CATALINA_BASE -classpath $EXEC_CLASSPATH uk.co.develop4.security.tomcatutils.cli.DecoderCli configuration=${DECODER_PROPERTIES} $*
