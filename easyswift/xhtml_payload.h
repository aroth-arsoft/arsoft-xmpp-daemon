/*
 * Copyright (c) 2011 Jan Kaluza
 * Licensed under the Simplified BSD license.
 * See Documentation/Licenses/BSD-simplified.txt for more information.
 */

#pragma once

#include <vector>
#include <string>
#include <Swiften/Serializer/GenericPayloadSerializer.h>
#include <Swiften/Elements/Payload.h>
#include <Swiften/Parser/GenericPayloadParser.h>

namespace Swift {
    class XHTMLIMPayload : public Payload {
        public:
            XHTMLIMPayload(const std::string &body = "");

            const std::string& getBody() const { return body_; }

            void setBody(const std::string& body) {
                body_ = body;
            }

        private:
            std::string body_;
    };
    class SerializingParser;

    class XHTMLIMParser : public GenericPayloadParser<XHTMLIMPayload> {
        public:
            XHTMLIMParser();

            virtual void handleStartElement(const std::string& element, const std::string&, const AttributeMap& attributes);
            virtual void handleEndElement(const std::string& element, const std::string&);
            virtual void handleCharacterData(const std::string& data);
            boost::shared_ptr<XHTMLIMPayload> getLabelPayload() const;
        private:
            enum Level {
                TopLevel = 0,
                PayloadLevel = 1,
                BodyLevel = 2,
                InsideBodyLevel = 3
            };
            int level_;
            SerializingParser* bodyParser_;
            std::string currentText_;
    };

    class XHTMLIMSerializer : public GenericPayloadSerializer<XHTMLIMPayload> {
        public:
            XHTMLIMSerializer();

            virtual std::string serializePayload(boost::shared_ptr<XHTMLIMPayload> xhtml)  const;
    };
}
