#include <QApplication>
#include <QMainWindow>
#include <QTextEdit>
#include <QToolBar>
#include <QStatusBar>
#include <QMenuBar>
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QAction>
#include <QLabel>
#include <QFont>
#include <QRegularExpression>

class NotepadWindow : public QMainWindow {
    Q_OBJECT

public:
    NotepadWindow(QWidget *parent = nullptr) : QMainWindow(parent) {
        setWindowTitle("Notepad - Qt6 Example");
        resize(800, 600);

        editor = new QTextEdit(this);
        editor->setFont(QFont("Monospace", 12));
        setCentralWidget(editor);

        createActions();
        createMenus();
        createToolBar();
        createStatusBar();

        connect(editor, &QTextEdit::textChanged, this, &NotepadWindow::onTextChanged);
    }

private slots:
    void newFile() {
        if (maybeSave()) {
            editor->clear();
            currentFile.clear();
            setWindowTitle("Notepad - Qt6 Example");
        }
    }

    void openFile() {
        if (!maybeSave()) return;

        QString path = QFileDialog::getOpenFileName(this, "Open File", "",
            "Text Files (*.txt);;All Files (*)");
        if (path.isEmpty()) return;

        QFile file(path);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QMessageBox::warning(this, "Error", "Could not open file.");
            return;
        }

        QTextStream in(&file);
        editor->setPlainText(in.readAll());
        file.close();

        currentFile = path;
        setWindowTitle(path + " - Notepad");
        statusBar()->showMessage("Opened: " + path, 3000);
    }

    void saveFile() {
        if (currentFile.isEmpty()) {
            saveFileAs();
            return;
        }
        writeFile(currentFile);
    }

    void saveFileAs() {
        QString path = QFileDialog::getSaveFileName(this, "Save File", "",
            "Text Files (*.txt);;All Files (*)");
        if (path.isEmpty()) return;
        writeFile(path);
    }

    void about() {
        QMessageBox::about(this, "About",
            "<h2>Notepad</h2>"
            "<p>A simple Qt6 C++ GUI example.</p>"
            "<p>Features: New, Open, Save, Cut, Copy, Paste, Undo, Redo</p>");
    }

    void onTextChanged() {
        int words = editor->toPlainText().split(QRegularExpression("\\s+"),
            Qt::SkipEmptyParts).count();
        int chars = editor->toPlainText().length();
        wordCountLabel->setText(QString("  Words: %1  |  Chars: %2  ").arg(words).arg(chars));
    }

private:
    QTextEdit *editor;
    QString currentFile;
    QLabel *wordCountLabel;

    QAction *newAct;
    QAction *openAct;
    QAction *saveAct;
    QAction *saveAsAct;
    QAction *exitAct;
    QAction *undoAct;
    QAction *redoAct;
    QAction *cutAct;
    QAction *copyAct;
    QAction *pasteAct;

    void createActions() {
        newAct = new QAction("&New", this);
        newAct->setShortcut(QKeySequence::New);
        connect(newAct, &QAction::triggered, this, &NotepadWindow::newFile);

        openAct = new QAction("&Open...", this);
        openAct->setShortcut(QKeySequence::Open);
        connect(openAct, &QAction::triggered, this, &NotepadWindow::openFile);

        saveAct = new QAction("&Save", this);
        saveAct->setShortcut(QKeySequence::Save);
        connect(saveAct, &QAction::triggered, this, &NotepadWindow::saveFile);

        saveAsAct = new QAction("Save &As...", this);
        saveAsAct->setShortcut(QKeySequence::SaveAs);
        connect(saveAsAct, &QAction::triggered, this, &NotepadWindow::saveFileAs);

        exitAct = new QAction("E&xit", this);
        exitAct->setShortcut(QKeySequence::Quit);
        connect(exitAct, &QAction::triggered, this, &QWidget::close);

        undoAct = new QAction("&Undo", this);
        undoAct->setShortcut(QKeySequence::Undo);
        connect(undoAct, &QAction::triggered, editor, &QTextEdit::undo);

        redoAct = new QAction("&Redo", this);
        redoAct->setShortcut(QKeySequence::Redo);
        connect(redoAct, &QAction::triggered, editor, &QTextEdit::redo);

        cutAct = new QAction("Cu&t", this);
        cutAct->setShortcut(QKeySequence::Cut);
        connect(cutAct, &QAction::triggered, editor, &QTextEdit::cut);

        copyAct = new QAction("&Copy", this);
        copyAct->setShortcut(QKeySequence::Copy);
        connect(copyAct, &QAction::triggered, editor, &QTextEdit::copy);

        pasteAct = new QAction("&Paste", this);
        pasteAct->setShortcut(QKeySequence::Paste);
        connect(pasteAct, &QAction::triggered, editor, &QTextEdit::paste);
    }

    void createMenus() {
        QMenu *fileMenu = menuBar()->addMenu("&File");
        fileMenu->addAction(newAct);
        fileMenu->addAction(openAct);
        fileMenu->addAction(saveAct);
        fileMenu->addAction(saveAsAct);
        fileMenu->addSeparator();
        fileMenu->addAction(exitAct);

        QMenu *editMenu = menuBar()->addMenu("&Edit");
        editMenu->addAction(undoAct);
        editMenu->addAction(redoAct);
        editMenu->addSeparator();
        editMenu->addAction(cutAct);
        editMenu->addAction(copyAct);
        editMenu->addAction(pasteAct);

        QMenu *helpMenu = menuBar()->addMenu("&Help");
        QAction *aboutAct = new QAction("&About", this);
        connect(aboutAct, &QAction::triggered, this, &NotepadWindow::about);
        helpMenu->addAction(aboutAct);
    }

    void createToolBar() {
        QToolBar *toolbar = addToolBar("Main");
        toolbar->addAction(newAct);
        toolbar->addAction(openAct);
        toolbar->addAction(saveAct);
        toolbar->addSeparator();
        toolbar->addAction(undoAct);
        toolbar->addAction(redoAct);
        toolbar->addSeparator();
        toolbar->addAction(cutAct);
        toolbar->addAction(copyAct);
        toolbar->addAction(pasteAct);
    }

    void createStatusBar() {
        wordCountLabel = new QLabel("  Words: 0  |  Chars: 0  ");
        statusBar()->addPermanentWidget(wordCountLabel);
        statusBar()->showMessage("Ready", 3000);
    }

    void writeFile(const QString &path) {
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(this, "Error", "Could not save file.");
            return;
        }
        QTextStream out(&file);
        out << editor->toPlainText();
        file.close();

        currentFile = path;
        setWindowTitle(path + " - Notepad");
        statusBar()->showMessage("Saved: " + path, 3000);
    }

    bool maybeSave() {
        if (!editor->document()->isModified()) return true;

        auto ret = QMessageBox::warning(this, "Unsaved Changes",
            "The document has been modified.\nSave changes?",
            QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);

        if (ret == QMessageBox::Save) { saveFile(); return true; }
        if (ret == QMessageBox::Discard) return true;
        return false;
    }
};

#include "main.moc"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    NotepadWindow window;
    window.show();
    return app.exec();
}
