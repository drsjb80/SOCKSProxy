import java.net.*;
import java.io.*;
import java.util.Vector;
import java.util.Enumeration;

import java.util.logging.ConsoleHandler;
import java.util.logging.Level;

import edu.mscd.cs.javaln.*;

class SOCKSave extends Thread
{
    private static JavaLN logger = new JavaLN();
    private static ConsoleHandler CH = new ConsoleHandler();

    static
    {
        CH.setFormatter (new LineNumberFormatter());
        CH.setLevel (Level.FINER);
        logger.addHandler (CH);
        logger.setUseParentHandlers (false);
        logger.setLevel (Level.FINER);
    }

    private String url;
    private boolean head;
    private boolean onedotone;
    private Socket socket;

    public SOCKSave (Socket socket)
    {
        this.socket = socket;
    }

    private int readChar (InputStream IS)
    {
        try
        {
            return (IS.read());
        }
        catch (IOException IOE)
        {
            logger.warning (IOE);
            return (-1);
        } 
    }

    /*
    ** read a single (header) line that terminates with a \r\n
    */
    public String readLine (InputStream IS)
    {
        logger.entering();

        String ret = "";
        
        for (;;)
        {
            int c = readChar (IS);
            logger.finest ((char) c);

            if (c == -1)
            {
                logger.exiting (null);
                return (null);
            }

            if (c == '\r')
            {
                c = readChar (IS);

                if (c == '\n')
                {
                    logger.exiting (ret);
                    return (ret);
                }
                else
                {
                    logger.exiting (null);
                    return (null);
                }
            }
            else
            {
                ret += (char) c;
            }
        }
    }

    /*
    ** read through the header lines and save an array of them
    */
    public Vector getHeaderFields (InputStream IS)
    {
        logger.entering();

        Vector ret = new Vector();

        for (;;)
        {
            String s = readLine (IS);
            logger.finer (s);

            if (s == null)
                return (null);
            
            if (s.equals (""))
                break;

            ret.add (s);
        }

        logger.exiting (ret);
        return (ret);
    }

    /*
    ** look through the array of headers looking for a specific one
    */
    private String getMatch (Vector v, String match)
    {
        logger.entering (match);

        for (Enumeration e = v.elements(); e.hasMoreElements() ;)
        {
            String s = (String) e.nextElement();
            if (s.toUpperCase().startsWith (match.toUpperCase()))
            {
                logger.exiting (s);
                return (s);
            }
        }

        return (null);
    }

    /*
    ** does the header specify the length?
    */
    public int getContentLength (Vector headerFields)
    {
        int contentLength = -1;
        String t = getMatch (headerFields, "Content-Length:");

        if (t != null)
        {
            String a[] = t.split (" ");
            contentLength = Integer.parseInt (a[1]);
        }

        logger.exiting (contentLength);
        return (contentLength);
    }

    private void firstLine (String s)
    {
        logger.entering (s);

        if (s.toUpperCase().startsWith ("HEAD"))
        {
            head = true;
        }
        else if (s.toUpperCase().startsWith ("GET") ||
            s.toUpperCase().startsWith ("POST"))
        {
            String a[] = s.split (" ");

            url = a[1];
            logger.finer (url);

            onedotone = a[2].endsWith ("1.1");
            logger.finer (onedotone);

            /*
            URL url = null;

            try
            {
                url = new URL (a[1]);
            }
            catch (MalformedURLException MUE)
            {
                logger.warning (MUE);
                return (s);
            }

            path = host + url.getPath() +
                (url.getQuery() == null ? "" : "?" + url.getQuery()) +
                (url.getRef() == null ? "" : url.getRef());

            logger.finer (path);
            */
        }
    }

    private int getResponseCode (String s)
    {
        logger.entering (s);

        if (s.toUpperCase().startsWith ("HTTP"))
        {
            String a[] = s.split (" ");

            logger.exiting (Integer.parseInt (a[1]));
            return (Integer.parseInt (a[1]));
        }
        else
        {
            logger.severe ("No HTTP header");
            logger.exiting (-1);
            return (-1);

        }
    }

    /*
    ** read from an input stream that we don't know the length of
    */
    public void readUnknown (InputStream IS, OutputStream copy)
    {
        logger.entering();

        final int bufflen = 8192;
        byte buffer[] = new byte[bufflen];

        for (;;)
        {
            int read = -1;

            try
            {
                read = IS.read (buffer, 0, bufflen);
                logger.finer ("read = " + read);
            }
            catch (IOException IOE)
            {
                logger.warning (IOE);
                break;
            }

            if (read == -1)
                break;

            if (copy != null)
            {
                try
                {
                    copy.write (buffer, 0, read);
                }
                catch (IOException IOE)
                {
                    logger.warning (IOE);
                }
            }
        }
    }

    /*
    ** read from a stream and write to both the other end, and a file.
    ** read only up a a specific length.
    */
    private void readAndWriteLen (InputStream IS, OutputStream copy, int len)
    {
        logger.entering (len);

        final int bufflen = 8192;
        byte buffer[] = new byte[bufflen];
        int read = -1;

        int remaining = len;

        for (;;)
        {
            try
            {
                read = IS.read (buffer, 0,
                    remaining < bufflen ? remaining : bufflen);
                logger.finer ("read = " + read);
            }
            catch (IOException IOE)
            {
                logger.warning (IOE);
            }

            if (read == -1)
            {
                logger.warning ("unexpected end of file");
                break;
            }

            if (copy != null)
            {
                try
                {
                    copy.write (buffer, 0, read);
                }
                catch (IOException IOE)
                {
                    logger.warning (IOE);
                }
            }

            remaining -= read;

            if (remaining == 0)
                break;
        }

        logger.exiting();
    }

    /*
    ** Each chunk starts with the number of octets of the data it embeds
    ** expressed in hexadecimal followed by optional parameters (chunk
    ** extension) and a terminating CRLF sequence, followed by the chunk data.
    ** The chunk is terminated by CRLF.
    **
    ** The last-chunk is a regular chunk, with the exception that its length
    ** is zero.
    **
    ** The last-chunk is followed by the trailer, which consist of a (possibly
    ** empty) sequence of entity header fields.
    */

/*
4CRLF
WikiCRLF
5CRLF
pediaCRLF
ECRLF
 inCRLF
CRLF
chunks.CRLF
0CRLF
CRLF
CRLF
*/
/*
Wikipedia in

chunks.
*/

    private void copyChunked (InputStream IS, OutputStream copy)
    {
        logger.entering();

        for (;;)
        {
            String hex = readLine (IS);

            int count = Integer.parseInt (hex, 16);

            logger.finer (hex);
            logger.finer (count);
            
            if (count == 0)
            {
                /*
                ** read and ignore trailing CRLF of last chunk
                */
                readLine (IS);

                break;
            }

            readAndWriteLen (IS, copy, count);

            /*
            ** read and ignore trailing CRLF for this chunk
            */
            readLine (IS);
        }

        /*
        ** read and ignore any trailer
        */
        getHeaderFields (IS);

        logger.exiting();
    }

    /*
    ** get what we need from the HTTP request
    */
    private boolean readRequest (PipedInputStream requestIS)
    {
        for (;;)
        {
            Vector hf = getHeaderFields (requestIS);

            if (hf == null)
                return (false);

            firstLine ((String) hf.elementAt (0));
        }
    }

    private boolean readResponse (PipedInputStream responseIS)
    {
        readUnknown (responseIS, null);

        return (false);
    }

    public void run()
    {
        PipedInputStream requestIS = null;
        PipedOutputStream requestOS = null;
        PipedInputStream responseIS = null;
        PipedOutputStream responseOS = null;
        InputStream localIS = null;
        OutputStream localOS = null;

        try
        {
            requestIS = new PipedInputStream();
            requestOS = new PipedOutputStream (requestIS);
            responseIS = new PipedInputStream();
            responseOS = new PipedOutputStream (responseIS);

            localIS = socket.getInputStream();
            localOS = socket.getOutputStream();
        }
        catch (IOException IOE)
        {
            logger.warning (IOE);
            return;
        } 

        Thread t = new SOCKSProxy (localIS, localOS, requestOS, responseOS);

        t.start();

        boolean req = true;
        boolean res = true;

        for (;;)
        {
            /*
            ** it's possible for the request stream to be closed, but there
            ** is still info in the response stream.
            */
            if (req)
                req = readRequest (requestIS);

            if (res)
                res = readResponse (responseIS);

            if (!req && !res)
                break;
        }

        try
        {
            t.join();
        }
        catch (InterruptedException IE)
        {
            logger.warning (IE);
            return;
        } 

        try
        {
            localIS.close();
            localOS.close();
            requestIS.close();
            requestOS.close();
            responseIS.close();
            responseOS.close();
            socket.close();
        }
        catch (IOException IOE)
        {
            logger.throwing (IOE);
        }
    }

    public static void main (String args[])
    {
        try
        {
            ServerSocket serverSocket = new ServerSocket (1080);

            for (;;)
            {
                Socket socket = serverSocket.accept();
                new SOCKSave (socket).start();
            }
        }
        catch (IOException IOE)
        {
            logger.warning (IOE);
        } 
    }
}
