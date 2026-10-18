import QtQuick 2.2
import QtWebEngine 1.0

WebEngineView {
    id: view
    width: 1280
    height: 720

    onLoadingChanged: function(loadingInfo) {
        if (loadingInfo.status == WebEngineView.LoadStartedStatus)
            return;

        var ok = loadingInfo.status == WebEngineView.LoadSucceededStatus;
        view.runJavaScript(thumbnailer.afterLoadScript(), function() {
            thumbnailer.createThumbnail(ok);
        });
    }
}
