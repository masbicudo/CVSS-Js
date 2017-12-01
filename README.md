# CVSS-Js
CVSS library for Javascript

Actually it is made using Typescript and then compiled to Javascript.

Only CVSS 2 is supported at this moment.

Example
-----

```
var c = CVSS2.parseMetricsString('AV:N/AC:L/Au:N/C:N/I:N/A:C');
var s = c.baseScore();

var btc = c.fillParse('E:U/RL:OF/RC:UC');  // best temporal parameters
var bts = c.temporalScore();               // get the best temporal score

var Au = c.Au; // getting one of the CVSS parameters value (not the string)
```

License
-------

MIT - do whatever you wish, don't blame me... but I'll be glad to help if you have any trouble =D