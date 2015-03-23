var express = require('express');
var crypto = require('crypto');
var sanitizer = require('sanitizer');
var sqlite3 = require('sqlite3').verbose();
var date = require('date-format-lite');

// Generic Functions

function sha256(input) {
    var hash = crypto.createHash('sha256').update(input).digest('hex');
    return hash;
}

function numtochar(j) {
    if (j <= 6) {
        return "0";
    }
    else if (j <= 13) {
        return "1";
    }
    else if (j <= 20) {
        return "2";
    }
    else if (j <= 27) {
        return "3";
    }
    else if (j <= 34) {
        return "4";
    }
    else if (j <= 41) {
        return "5";
    }
    else if (j <= 48) {
        return "6";
    }
    else if (j <= 55) {
        return "7";
    }
    else if (j <= 62) {
        return "8";
    }
    else if (j <= 69) {
        return "9";
    }
    else if (j <= 76) {
        return "a";
    }
    else if (j <= 83) {
        return "b";
    }
    else if (j <= 90) {
        return "c";
    }
    else if (j <= 97) {
        return "d";
    }
    else if (j <= 104) {
        return "e";
    }
    else if (j <= 111) {
        return "f";
    }
    else if (j <= 118) {
        return "g";
    }
    else if (j <= 125) {
        return "h";
    }
    else if (j <= 132) {
        return "i";
    }
    else if (j <= 139) {
        return "j";
    }
    else if (j <= 146) {
        return "k";
    }
    else if (j <= 153) {
        return "l";
    }
    else if (j <= 160) {
        return "m";
    }
    else if (j <= 167) {
        return "n";
    }
    else if (j <= 174) {
        return "o";
    }
    else if (j <= 181) {
        return "p";
    }
    else if (j <= 188) {
        return "q";
    }
    else if (j <= 195) {
        return "r";
    }
    else if (j <= 202) {
        return "s";
    }
    else if (j <= 209) {
        return "t";
    }
    else if (j <= 216) {
        return "u";
    }
    else if (j <= 223) {
        return "v";
    }
    else if (j <= 230) {
        return "w";
    }
    else if (j <= 237) {
        return "x";
    }
    else if (j <= 244) {
        return "y";
    }
    else if (j <= 251) {
        return "z";
    }
    else return "e";
}

function makeV2addr(key) {
    var protein = ["", "", "", "", "", "", "", "", ""];
    var link = 0;
    var v2 = "k";
    var stick = sha256(sha256(key));
    for (var i = 0; i <= 9; i++) {
        if (i < 9) {
            protein[i] = stick.substring(0, 2);
            stick = sha256(sha256(stick));
        }
    }
    i = 0;
    while (i <= 8) {
        link = parseInt(stick.substring(2 * i, 2 + (2 * i)), 16) % 9;
        if (protein[link] == "") {
            stick = sha256(stick);
        }
        else {
            v2 = v2 + numtochar(parseInt(protein[link], 16));
            protein[link] = "";
            i++;
        }

    }
    return v2;
}

function sprintf() {
    //  discuss at: http://phpjs.org/functions/sprintf/
    // original by: Ash Searle (http://hexmen.com/blog/)
    // improved by: Michael White (http://getsprink.com)
    // improved by: Jack
    // improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
    // improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
    // improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
    // improved by: Dj
    // improved by: Allidylls
    //    input by: Paulo Freitas
    //    input by: Brett Zamir (http://brett-zamir.me)
    //   example 1: sprintf("%01.2f", 123.1);
    //   returns 1: 123.10
    //   example 2: sprintf("[%10s]", 'monkey');
    //   returns 2: '[    monkey]'
    //   example 3: sprintf("[%'#10s]", 'monkey');
    //   returns 3: '[####monkey]'
    //   example 4: sprintf("%d", 123456789012345);
    //   returns 4: '123456789012345'
    //   example 5: sprintf('%-03s', 'E');
    //   returns 5: 'E00'

    var regex = /%%|%(\d+\$)?([-+\'#0 ]*)(\*\d+\$|\*|\d+)?(\.(\*\d+\$|\*|\d+))?([scboxXuideEfFgG])/g;
    var a = arguments;
    var i = 0;
    var format = a[i++];

    // pad()
    var pad = function(str, len, chr, leftJustify) {
        if (!chr) {
            chr = ' ';
        }
        var padding = (str.length >= len) ? '' : new Array(1 + len - str.length >>> 0)
            .join(chr);
        return leftJustify ? str + padding : padding + str;
    };

    // justify()
    var justify = function(value, prefix, leftJustify, minWidth, zeroPad, customPadChar) {
        var diff = minWidth - value.length;
        if (diff > 0) {
            if (leftJustify || !zeroPad) {
                value = pad(value, minWidth, customPadChar, leftJustify);
            }
            else {
                value = value.slice(0, prefix.length) + pad('', diff, '0', true) + value.slice(prefix.length);
            }
        }
        return value;
    };

    // formatBaseX()
    var formatBaseX = function(value, base, prefix, leftJustify, minWidth, precision, zeroPad) {
        // Note: casts negative numbers to positive ones
        var number = value >>> 0;
        prefix = prefix && number && {
            '2': '0b',
            '8': '0',
            '16': '0x'
        }[base] || '';
        value = prefix + pad(number.toString(base), precision || 0, '0', false);
        return justify(value, prefix, leftJustify, minWidth, zeroPad);
    };

    // formatString()
    var formatString = function(value, leftJustify, minWidth, precision, zeroPad, customPadChar) {
        if (precision != null) {
            value = value.slice(0, precision);
        }
        return justify(value, '', leftJustify, minWidth, zeroPad, customPadChar);
    };

    // doFormat()
    var doFormat = function(substring, valueIndex, flags, minWidth, _, precision, type) {
        var number, prefix, method, textTransform, value;

        if (substring === '%%') {
            return '%';
        }

        // parse flags
        var leftJustify = false;
        var positivePrefix = '';
        var zeroPad = false;
        var prefixBaseX = false;
        var customPadChar = ' ';
        var flagsl = flags.length;
        for (var j = 0; flags && j < flagsl; j++) {
            switch (flags.charAt(j)) {
                case ' ':
                    positivePrefix = ' ';
                    break;
                case '+':
                    positivePrefix = '+';
                    break;
                case '-':
                    leftJustify = true;
                    break;
                case "'":
                    customPadChar = flags.charAt(j + 1);
                    break;
                case '0':
                    zeroPad = true;
                    customPadChar = '0';
                    break;
                case '#':
                    prefixBaseX = true;
                    break;
            }
        }

        // parameters may be null, undefined, empty-string or real valued
        // we want to ignore null, undefined and empty-string values
        if (!minWidth) {
            minWidth = 0;
        }
        else if (minWidth === '*') {
            minWidth = +a[i++];
        }
        else if (minWidth.charAt(0) == '*') {
            minWidth = +a[minWidth.slice(1, -1)];
        }
        else {
            minWidth = +minWidth;
        }

        // Note: undocumented perl feature:
        if (minWidth < 0) {
            minWidth = -minWidth;
            leftJustify = true;
        }

        if (!isFinite(minWidth)) {
            throw new Error('sprintf: (minimum-)width must be finite');
        }

        if (!precision) {
            precision = 'fFeE'.indexOf(type) > -1 ? 6 : (type === 'd') ? 0 : undefined;
        }
        else if (precision === '*') {
            precision = +a[i++];
        }
        else if (precision.charAt(0) == '*') {
            precision = +a[precision.slice(1, -1)];
        }
        else {
            precision = +precision;
        }

        // grab value using valueIndex if required?
        value = valueIndex ? a[valueIndex.slice(0, -1)] : a[i++];

        switch (type) {
            case 's':
                return formatString(String(value), leftJustify, minWidth, precision, zeroPad, customPadChar);
            case 'c':
                return formatString(String.fromCharCode(+value), leftJustify, minWidth, precision, zeroPad);
            case 'b':
                return formatBaseX(value, 2, prefixBaseX, leftJustify, minWidth, precision, zeroPad);
            case 'o':
                return formatBaseX(value, 8, prefixBaseX, leftJustify, minWidth, precision, zeroPad);
            case 'x':
                return formatBaseX(value, 16, prefixBaseX, leftJustify, minWidth, precision, zeroPad);
            case 'X':
                return formatBaseX(value, 16, prefixBaseX, leftJustify, minWidth, precision, zeroPad)
                    .toUpperCase();
            case 'u':
                return formatBaseX(value, 10, prefixBaseX, leftJustify, minWidth, precision, zeroPad);
            case 'i':
            case 'd':
                number = +value || 0;
                // Plain Math.round doesn't just truncate
                number = Math.round(number - number % 1);
                prefix = number < 0 ? '-' : positivePrefix;
                value = prefix + pad(String(Math.abs(number)), precision, '0', false);
                return justify(value, prefix, leftJustify, minWidth, zeroPad);
            case 'e':
            case 'E':
            case 'f': // Should handle locales (as per setlocale)
            case 'F':
            case 'g':
            case 'G':
                number = +value;
                prefix = number < 0 ? '-' : positivePrefix;
                method = ['toExponential', 'toFixed', 'toPrecision']['efg'.indexOf(type.toLowerCase())];
                textTransform = ['toString', 'toUpperCase']['eEfFgG'.indexOf(type) % 2];
                value = prefix + Math.abs(number)[method](precision);
                return justify(value, prefix, leftJustify, minWidth, zeroPad)[textTransform]();
            default:
                return substring;
        }
    };

    return format.replace(regex, doFormat);
}

function isAlphanumeric(str) {
    return str.search(/^[a-z0-9]+$/i) == 0;
}

function isHex(str) {
    return str.search(/^[a-f0-9]+$/i) == 0;
}

// Open database
var db = new sqlite3.Database("data.db", sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, function(err) {
    if (err) {
        console.log("Failed to open database");
        throw (err);
    }
    else {
        console.log("Database opened successfully");
        startNode();
    }
});

function startNode() {
    // Build node

    var app = express();

    app.get('/', function(req, res) {
        var getData = req.query;

        if (typeof getData.v2 !== undefined && getData.v2) {
            // ?v2=<private key>
            // Generates an address for the provided private key
            getData.v2 = sanitizer.sanitize(getData.v2);
            res.send(makeV2addr(getData.v2));
            res.end();
        }
        else if (getData.getbalance) {
            // ?getbalance=<address>
            // Returns the balance for an address
            var stmt = db.prepare("SELECT balance FROM addresses WHERE address = (?)");
            stmt.get(getData.getbalance, function(err, row) {
                if (err) {
                    res.send("Internal Error");
                    res.end();
                    throw (err);
                }
                else {
                    res.send(row.balance.toString());
                    res.end();
                }
            });
        }
        else if (getData.blocks === '') {
            // ?blocks
            // ?blocks&low
            // ?blocks&lownonce
            // ?blocks&highnonce
            var limit = 17;
            var order = "id DESC";
            var str = "";
            if (getData.low === '') {
                limit = 18;
                order = "hash ASC";
            }
            else if (getData.lownonce === '') {
                order = "nonce ASC";
            }
            else if (getData.highnonce === '') {
                order = "nonce DESC";
            }
            var stmt = db.prepare("SELECT * FROM blocks WHERE id > 0 ORDER BY " + order + " LIMIT (?)");
            stmt.all(limit, function(err, rows) {
                if (err) {
                    res.send("Internal Error");
                    res.end();
                    throw (err);
                }
                else {
                    for (var i = 0; i < rows.length; i++) {
                        var time = new Date(rows[i].time * 1000);
                        if (i == 0 && !(getData.low === '')) {
                            str += sprintf("%08d", rows[i].id);
                        }
                        if (i == 0 && !(getData.low == '')) {
                            str += time.toISOString().substring(0, 10);
                        }
                        if (rows[i].address === '' || rows[i].address == 'N\\A' || rows[i].address == '2bb037a6f' || rows[i].address == 'C:\\Users\\Bryan\\Downloads\\miner.py') {
                            rows[i].address = "N/A(Burnt)";
                        }
                        if (getData.low === '') {
                            var feat = rows[i].hash.substring(0, 20);
                            if (getData.lownonce === '' || getData.highnonce === '') {
                                feat = sprintf("%012d", rows[i].nonce);
                            }
                            str += time.format("MMM DD") + sprintf("%06d", rows[i].id) + feat;
                        }
                        else {
                            str += time.format("hh:mm:ss") + rows[i].address.substring(0, 10) + rows[i].hash.substring(0, 12);
                        }
                    }
                    res.send(str);
                    res.end();
                }
            });
        }
        else if (getData.richapi === '') {
            // ?richapi
            var stmt = db.prepare('SELECT * FROM addresses ORDER BY balance DESC LIMIT (?)');
            // Limit is currently fixed but may be changeable later
            var limit = 16;
            var str = "";
            stmt.all(limit, function(err, rows) {
                if (err) {
                    res.send("Internal Error");
                    res.end();
                    throw (err);
                }
                else {
                    for (var i = 0; i < rows.length; i++) {
                        var firsttime = new Date(rows[i].firstseen * 1000);
                        str += rows[i].address.substring(0, 10);
                        str += sprintf("%08d", rows[i].balance);
                        str += firsttime.format("DD MMM YYYY");
                    }
                    res.send(str);
                    res.end();
                }
            });
        }
        else if (getData.recenttx === '') {
            // ?recenttx
            // ?recenttx&lots
            var limit = 32;
            if (getData.lots === '') {
                limit = 20000;
            }
            var stmt = db.prepare('SELECT * FROM transactions WHERE (`from` != "") ORDER BY time DESC LIMIT (?)');
            stmt.all(limit, function(err, rows) {
                if (err) {
                    res.send("Internal Error");
                    res.end();
                    throw (err);
                }
                else {
                    var str = "";
                    for (var i = 0; i < rows.length; i++) {
                        var time = new Date(rows[i].time * 1000);
                        str += time.format("MMM DD hh:mm");
                        str += rows[i].from;
                        str += rows[i].to;
                        str += sprintf("%08d", Math.abs(rows[i].value));
                    }
                    res.send(str);
                    res.end();
                }
            });
        }
        else if (typeof getData.listtx !== undefined && getData.listtx) {
            // ?listtx=<address>
            // ?listtx=<address>&overview
            var limit = 15984;
            if (getData.overview === '') {
                limit = 3;
            }
            if ((getData.listtx.length === 10) &&
                ((getData.listtx.substring(0, 1) === "k" && isAlphanumeric(getData.listtx))) ||
                (isHex(getData.listtx))) {
                var params = [sanitizer.sanitize(getData.listtx), sanitizer.sanitize(getData.listtx), limit];
                var stmt = db.prepare('SELECT * FROM transactions WHERE ("to" = ? OR "from" = ?) ORDER BY time DESC LIMIT ?');
                stmt.all(params, function(err, rows) {
                    if (err) {
                        res.send("Internal Error");
                        res.end();
                        throw (err);
                    }
                    else {
                        var str = ""
                        for (var i = 0; i < rows.length; i++) {
                            var time = new Date(rows[i].time * 1000);
                            var sign;
                            var peer;
                            if (rows[i].to === getData.listtx) {
                                peer = rows[i].from;
                                sign = "+";
                            }
                            else {
                                peer = rows[i].to;
                                sign = "-";
                            }
                            if (rows[i].from.length < 10) {
                                peer = "N/A(Mined)";
                            }
                            str += time.format("MMM DD hh:mm");
                            str += peer;
                            str += sign;
                            str += sprintf("%08d", Math.abs(rows[i].value));
                        }
                        res.send(str + "end");
                        res.end();
                    }
                });

            }
            else {
                res.send("Error4");
                res.end();
            }
        }
        else {
            res.send("Malformed GET data");
            res.end();
        }
    });

    // POST not supported yet
    app.post('/', function(req, res) {
        res.send("POST is not supported");
        res.end();
    });

    var server = app.listen(process.env.PORT, function() {
        var host = server.address().address;
        var port = server.address().port;
        console.log("Started Krist node at " + host + ":" + port);
    });
}
