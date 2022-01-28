let x = "ABC";
let v = {1:2};

v.toString = function() { return x; };
let s = `XYZ${v}`;

for (let i = 0; i < 3; i++) {
    s = v[1];
    v[1] = v;
}
