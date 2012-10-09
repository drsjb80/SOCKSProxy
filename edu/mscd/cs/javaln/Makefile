BASE	= $*
TARGET	= $@
DEPENDS	= $<
NEWER	= $?

PACKAGE	= edu.mscd.cs.javaln
DIR	= edu/mscd/cs/javaln
ROOT	= ../../../..
CP	= -classpath $(ROOT)

JAVALN	= JavaLN.java LineNumberFormatter.java NullFormatter.java \
	  LevelFilter.java Test.java Version.java Package.java \
	  SetFilter.java

JSRC	= $(JAVALN)
DJSRC	= $(patsubst %,$(DIR)/%,$(JSRC))

CLASSES = $(JSRC:.java=.class) One.class Two.class Three.class Four.class
DCLASSES = $(patsubst %,$(DIR)/%,$(CLASSES))

SYSLOG	= syslog/Makefile syslog/*.java syslog/*.class syslog/*.[ch] \
	  syslog/*.props
DSYSLOG	= $(patsubst %,$(DIR)/%,$(SYSLOG))

MISC	= Makefile MainClass top.html bot.html index.html \
	  LevelFilter.props LineNumberFormatter.props \
	  NullFormatter.props getClass UPLOAD VERSION
DMISC	= $(patsubst %,$(DIR)/%,$(MISC))

ALL	= $(JSRC) $(CLASSES) $(SYSLOG) package.html doc $(MISC)
DALL	= $(DJSRC) $(DCLASSES) $(DCSRC) $(DSYSLOG) $(DIR)/package.html \
	  $(DIR)/doc $(DMISC) $(DJNILIBS)

VERSION = $(shell cat VERSION)
JAR	= JavaLN-$(VERSION).jar

.SUFFIXES: .java .class

.java.class : 
	javac -source 1.2 -target 1.2 $(CP) -Xlint:deprecation -Xlint:unchecked $(DEPENDS)

$(JAR) : $(ALL)
	cd syslog; make
	cd $(ROOT) ; jar cMf $(DIR)/$(TARGET) $(DALL)

doc : $(JSRC) syslog/*.java
	javadoc -quiet -d doc $(JSRC) syslog/*.java
	touch doc

clean : 
	cd syslog; make clean
	rm -f $(CLASSES) $(JAR)

test : testBasic testPackage testClassFilter testJavaLN \
	testVersion testLevelFilter testLineNumberFormatter testNullFormatter

testBasic : Test.class JavaLN.class LineNumberFormatter.class
	java $(CP):. Test 2>&1 | ./rmdate | tee /tmp/$(TARGET).good
	./rmdate < $(TARGET).good | diff /tmp/$(TARGET).good -
	rm /tmp/$(TARGET).good

testPackage : Package.class JavaLN.class
	java $(CP) $(PACKAGE).Package
	./rmdate < $(TARGET).good | diff /tmp/$(TARGET).good -
	rm /tmp/$(TARGET).good

testClassFilter : SetFilter.class
	java $(CP) $(PACKAGE).ClassFilter

testMethodFilter : SetFilter.class
	java $(CP) $(PACKAGE).MethodFilter

testJavaLN : JavaLN.class LineNumberFormatter.class
	java $(CP) $(PACKAGE).JavaLN

testVersion : $(JAR)
	java $(CP) $(PACKAGE).Version

testLevelFilter : LevelFilter.class
	java $(CP) $(PACKAGE).LevelFilter > /tmp/$$$$ 2>&1 ; \
		diff /tmp/$$$$ LevelFilter.good ; \
		rm /tmp/$$$$
	java $(CP) -Djava.util.logging.config.file=LevelFilter.props \
		$(PACKAGE).Test

testLineNumberFormatter : LineNumberFormatter.class LineNumberFormatter.props
	java $(CP) $(PACKAGE).LineNumberFormatter
	# java $(CP) -Djava.util.logging.config.file=LineNumberFormatter.props \
		# $(PACKAGE).Test

testNullFormatter : NullFormatter.class NullFormatter.props
	java $(CP) $(PACKAGE).NullFormatter
	java $(CP) -Djava.util.logging.config.file=NullFormatter.props \
		$(PACKAGE).Test

ORDER	= JavaLN LineNumberFormatter NullFormatter LevelFilter MethodFilter \
	  syslog/CLIFormatter.java syslog/CLIHandler.java \
	  syslog/SyslogdFormatter.java syslog/SyslogdHandler.java \
	  syslog/SyslogFormatter.java syslog/SyslogHandler.java \
	  syslog/UNIXDomainHandler.java \

index.html : getClass top.html bot.html
	cat top.html > $(TARGET)
	for i in $(ORDER); \
	do \
	    ./getClass NAME=$$i < doc/package-summary.html >> $(TARGET);\
	done
	cat bot.html >> $(TARGET)

Version.java : VERSION
	echo "package edu.mscd.cs.javaln; public class Version { public static String getVersion() { return (\"$(VERSION)\"); } public static void main (String args[]) { System.out.println (getVersion()); }}" > $(TARGET)
