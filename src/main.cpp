#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("dis");
    app.setOrganizationName("dis");

    MainWindow window;
    window.show();

    // Auto-load file from command line or default
    if (argc > 1) {
        window.loadFile(argv[1]);
    }

    return app.exec();
}
