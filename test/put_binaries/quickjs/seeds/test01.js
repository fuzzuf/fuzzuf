let arr = [1.1, 2.2, 3.3];
arr.shift();
let l = arr.length;
arr[1] = arr[l-1] + arr[0];
let v = arr.toString();
