
let v: any; (v as any) = 2; v! = 3; (<any>v) = 4; (v satisfies any) = 5;
const fn = f<string>; ({ a: (v as any) } = o); [(v!)] = arr;
for ((v as any) of list) {}
