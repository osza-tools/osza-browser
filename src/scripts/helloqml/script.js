function init() {
    external.extra.helloQmlObject.clicked.connect(function(count){
        alert('You clicked ' + count + ' times')
    })
}

if (window._veex_external) {
    init();
} else {
    document.addEventListener("_veex_external_created", init);
}
