const ctx = document.getElementById('logChart');

if(ctx){

new Chart(ctx, {

type:'line',

data:{

labels:[
'Mon',
'Tue',
'Wed',
'Thu',
'Fri',
'Sat',
'Sun'
],

datasets:[{

label:'Logs',

data:[
120,
180,
250,
190,
320,
280,
410
]

}]

}

});

}