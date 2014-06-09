/*
 * Copyright (c) 2011 Jan Kaluza
 * Licensed under the Simplified BSD license.
 * See Documentation/Licenses/BSD-simplified.txt for more information.
 */

#include "xhtml_payload.h"
#include <Swiften/Base/foreach.h>
#include <Swiften/Parser/SerializingParser.h>
#include <Swiften/Serializer/XML/XMLRawTextNode.h>
#include <Swiften/Serializer/XML/XMLTextNode.h>
#include <Swiften/Serializer/XML/XMLElement.h>

namespace Swift {

XHTMLIMPayload::XHTMLIMPayload(const std::string &body) : body_(body) {
}

XHTMLIMParser::XHTMLIMParser() : level_(TopLevel), bodyParser_(0) {
}

void XHTMLIMParser::handleStartElement(const std::string& element, const std::string& ns, const AttributeMap& attributes) {
    ++level_;
    if (level_ == BodyLevel) {
        if (element == "body") {
            assert(!bodyParser_);
            bodyParser_ = new SerializingParser();
        }
    }
    else if (level_ >= InsideBodyLevel && bodyParser_) {
        bodyParser_->handleStartElement(element, "", attributes);
    }
}

void XHTMLIMParser::handleEndElement(const std::string& element, const std::string& ns) {
    if (level_ == BodyLevel) {
        if (bodyParser_) {
            if (element == "body") {
                getPayloadInternal()->setBody(bodyParser_->getResult());
            }
            delete bodyParser_;
            bodyParser_ = 0;
        }
    }
    else if (bodyParser_ && level_ >= InsideBodyLevel) {
        bodyParser_->handleEndElement(element, ns);
    }
    --level_;
}

void XHTMLIMParser::handleCharacterData(const std::string& data) {
    if (bodyParser_) {
        bodyParser_->handleCharacterData(data);
    }
    else {
        currentText_ += data;
    }
}

boost::shared_ptr<XHTMLIMPayload> XHTMLIMParser::getLabelPayload() const {
    return getPayloadInternal();
}

XHTMLIMSerializer::XHTMLIMSerializer() : GenericPayloadSerializer<XHTMLIMPayload>() {
}

std::string XHTMLIMSerializer::serializePayload(boost::shared_ptr<XHTMLIMPayload> payload)  const {
    XMLElement html("html", "http://jabber.org/protocol/xhtml-im");

    boost::shared_ptr<XMLElement> body(new XMLElement("body", "http://www.w3.org/1999/xhtml"));
    body->addNode(boost::shared_ptr<XMLRawTextNode>(new XMLRawTextNode(payload->getBody())));
    html.addNode(body);

    return html.serialize();
}

}
