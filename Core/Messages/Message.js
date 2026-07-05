import Severity from "./Severity.js";
import MessageCatalog from "./MessageCatalog.js";

export default class Message{

    constructor({ text = null, code = null, severity = null, data = null, titleData = null, catalog = MessageCatalog }) {

        const entry = code ? catalog?.map?.[code] : null;

        this.code = code || null;
        
        this.title = entry?.title || text || "Unknown Issue";
        if(titleData)
            this.title += " " + titleData;

        // we use data for additional informations
        this.details = entry?.details || "";
        if (data) {
            this.details = `${this.details} (${data})`;
        }

        this.category = entry?.category || "custom";

        this.severity =
            severity ||
            entry?.severity ||
            Severity.INFO;
    }
}