
This is a simple LFI process spy/brute-forcer.

## About
I made this because I needed it for a CTF-Challenge, but I thought it could be useful in other challenges/real life too.

```
Usage of ./program:
  -continue-on-success
        If you specify this option the script will run to the end and output every match found.
  -dump
        Dump 
  -ep int
        Specify the ending pid for fuzzing (This PID is included), change it for preformance. (default 100000)
  -ns string
        Add this string to filter for the content of a request. If the string appears, the process/cmdline is flagged as invalid. (default "XXXX")
  -output string
        You can output the data in a csv file.
  -remove-prefix string
        This can be used to clean up the contents of the output (file). - beta
  -remove-suffix string
        This can be used to clean up the contents of the output (file) -beta.
  -search string
        Search for a specific pattern inside the requests
  -sp int
        Specify the starting pid for fuzzing
  -t string
        The target URL you want to attack. In that format: http://target.url/location/for/lfi/?x=../../../*. Please add a star at the end of the string so the location for the LFI is set. (default "notarget")
  -us string
        What is the ouput if the process file is not accessable. (default "<pre></pre>")
```

In this repository there is an example server included for testing my script. There you can also test your own payloads/test LFI exploits.
