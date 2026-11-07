/* ============================================================
* Osza - Qt web browser
* Copyright (C) 2010-2018 David Rosca <nowrep@gmail.com>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
* ============================================================ */
#ifndef OSZASCHEMEHANDLER_H
#define OSZASCHEMEHANDLER_H

#include <QMutex>
#include <QBuffer>
#include <QIODevice>
#include <QUrl>
#include <QWebEngineUrlSchemeHandler>

#include "qzcommon.h"

class OSZA_EXPORT OszaSchemeHandler : public QWebEngineUrlSchemeHandler
{
public:
    explicit OszaSchemeHandler(QObject *parent = nullptr);

    void requestStarted(QWebEngineUrlRequestJob *job) Q_DECL_OVERRIDE;

private:
    bool handleRequest(QWebEngineUrlRequestJob *job);
};

class OSZA_EXPORT OszaSchemeReply : public QIODevice
{
    Q_OBJECT

public:
    explicit OszaSchemeReply(QWebEngineUrlRequestJob *job, QObject *parent = nullptr);

    qint64 bytesAvailable() const Q_DECL_OVERRIDE;
    qint64 readData(char *data, qint64 maxSize) Q_DECL_OVERRIDE;
    qint64 writeData(const char *data, qint64 len) Q_DECL_OVERRIDE;

private Q_SLOTS:
    void loadPage();

private:
    // The contents of the page the request's address names, built
    // from the request URL captured at construction time (on the
    // thread the request arrived on) - never from the job, which is
    // not safe to touch from the UI thread the build runs on.
    QString pageContents(const QString &pageName, const QUrl &requestUrl);

    QString aboutPage();
    QString startPage();
    QString speeddialPage();
    QString restorePage();
    QString configPage();

    bool m_loaded;
    QBuffer m_buffer;
    QString m_pageName;
    QUrl m_requestUrl;
    QWebEngineUrlRequestJob *m_job;
    mutable QMutex m_mutex;
};

#endif // OSZASCHEMEHANDLER_H
