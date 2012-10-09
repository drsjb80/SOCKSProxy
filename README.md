HTTProxyGrab
============
Here is some very raw Java code that acts as an HTTP proxy while saving the
stream of every request to a file on your local system.  This allows you to
capture anything that your browser understands, including the streams from
embedded video, audio, etc. streams.  Usage:

java HTTProxyGrab 8080
-or-
java -jar HTTProxyGrab.jar 8080

to have the program listen on port 8080 for requests.  Point your broswer's
HTTP proxy to 127.0.0.1, port 8080 and watch all the URL streams be saved.
The output includes what is being saved, and any errors that occur.

N.B.: I hacked this together in an hour or so for a very specific purpose.
Probably not ready for prime time, but useful enough as is.  Let me know if
you have any questions.  Thanks!
