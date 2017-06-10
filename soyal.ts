
/**
 * Para entrar como administrador:
 * 
 *   Pulsar: *, 123456, #
 */

namespace soyal {
    const ACK = 4;
    const NACK = 5;
    const EVENT_OK_CARD = 11;
    const EVENT_OK_FINGERPRINT = 39;
    const EVENT_ERR_Fingerprintidentifyfailed = 40;
    const EVENT_ERR_AccessviaFingerprint = 56;

    export function newReader(id: number, ip: string, port: number): amura.Reader {
        let dev = newDevice(id, ip, port);
        return {
            getTime: (loc: time.Location) => getTime(dev, loc),
            setTime: (t: time.Time) => setTime(dev, t),
            downloadLogs: (id: number, db: sql.DB, loc: time.Location) => downloadLogs(id, db, dev, loc),
            downloadUsers: (db: sql.DB) => downloadUsers(db, dev),
            uploadUsers: (db: sql.DB, users: number[]) => uploadusers(db, dev, users),
            deleteAllUsers: () => deleteAllUsers(dev)
        }
    }

    function deleteAllUsers(dev: Device) {
    }

    function downloadUsers(db: sql.DB, dev: Device): number {
        let count = 0;
        let empIDs = db.load("select id from employee where deleted=false");
        let model = amura.TerminalBioDataModel.Soyal;

        var mustClose;
        if (!dev.con) {
            dev.con = net.dial("tcp", dev.IPAddress + ":" + dev.port)
            mustClose = true;
        }
        try {
            // read cards
            // for (var emp of empIDs) {
            //     let buf = array.bytes(3);
            //     binary.putInt16BigEndian(buf, emp.id)
            //     buf[2] = 0x01;

            //     let data = newExtPacket(dev.id, 0x87, buf);
            //     dev.con.write(data)
            //     let echo = io.read(dev.con);
            //     binary.hexLog(echo)

            // }


            //read fingerprint templates
            pauseFingerprint(dev);
            for (var emp of empIDs) {
                let data: any = getFPTemplates(dev, emp.id);
                if (!data) {
                    continue;
                }

                db.beginTransaction()
                try {
                    db.exec("UPDATE terminalbiodata SET deleted=true WHERE employee=? AND model=?", emp.id, model);
                    amura.insertTerminalBioData(db, {
                        employee: emp.id,
                        model: model,
                        data: data
                    })
                    db.commit();
                }
                catch (e) {
                    db.rollback();
                    throw e;
                }

                count++;
            }
        }
        finally {
            restoreFingerprint(dev);
            if (mustClose) {
                dev.con.close();
                dev.con = null;
            }
        }
        return count;
    }

    function uploadusers(db: sql.DB, dev: Device, users: number[]): number {
        let count = 0;
        let data = amura.loadTerminalBioDatas(db,
            sql.where("model=?", amura.TerminalBioDataModel.Soyal)
                .and("employee in (" + users.join(",") + ")"));

        var mustClose;
        if (!dev.con) {
            dev.con = net.dial("tcp", dev.IPAddress + ":" + dev.port)
            mustClose = true;
        }
        try {
            pauseFingerprint(dev);
            for (var d of data) {
                deleteFPTemplates(dev, d.employee, d.employee);
                writeFPTemplates(dev, d.employee, convert.toBytes(d.data))
                count++;
            }
        }
        finally {
            restoreFingerprint(dev);
            if (mustClose) {
                dev.con.close();
                dev.con = null;
            }
        }
        return count;
    }

    interface Device {
        id: number;
        IPAddress: string
        port: number;
        con?: net.Connection;
    }

    function newDevice(id: number, ip: string, port: number): Device {
        return { id: id, IPAddress: ip, port: port }
    }

    function openCon(dev: Device) {
        dev.con = net.dial("tcp", dev.IPAddress + ":" + dev.port)
    }

    function closeCon(dev: Device) {
        dev.con.close();
        dev.con = null
    }

    /**
     * Implemented following:
     * Protocol_881E_725Ev2_82xEv5 3V06.pdf 
     * 1.3 Data Packet
     */
    function newPacket(destinationID: number, command: number, data?: number[]): number[] {
        let length = 4;
        let xor = 0xFF ^ destinationID ^ command;
        let sum = destinationID + command;
        if (data) {
            length += data.length;
            for (var b of data) {
                xor ^= b;
                sum += b;
            }
        }
        sum += xor;

        let buf = [0x7E, length, destinationID, command];
        if (data) {
            buf = buf.concat(data)
        }
        buf.push(xor);
        buf.push(sum);
        return buf;
    }

    /**
     * Implemented following:
     * Protocol_881E_725Ev2_82xEv5 3V06.pdf 
     * 1.3 Data Packet
     */
    function newExtPacket(destinationID: number, command: number, data?: number[]): number[] {
        let length = 4;
        let xor = 0xFF ^ destinationID ^ command;
        let sum = destinationID + command;
        if (data) {
            length += data.length;
            for (var b of data) {
                xor ^= b;
                sum += b;
            }
        }

        xor = xor % 256;
        sum += xor;
        sum = sum % 256;

        // length is 2 bytes
        let bLen = array.bytes(2);
        binary.putInt16BigEndian(bLen, length);

        let buf = [0xFF, 0x00, 0x5A, 0xA5, bLen[0], bLen[1], destinationID, command];
        if (data) {
            buf = buf.concat(data)
        }
        buf.push(xor);
        buf.push(sum);
        return buf;
    }

    function getFunctionCode(data: number[]): number {
        let extended = data[0] == 0xFF;
        let code = extended ? data[7] : data[3];
        return code;
    }

    function getDataByte(data: number[], index: number): number {
        let extended = data[0] == 0xFF;
        let start = extended ? 8 : 4;
        return data[start + index];
    }

    function check(data: number[]): number {
        let extended = data[0] == 0xFF;
        let start = extended ? 6 : 2;
        let code = extended ? data[7] : data[3];

        let xor = 0xFF;
        let sum = 0;
        let len = data.length - 2;

        for (var i = start; i < len; i++) {
            let d = data[i]
            xor ^= d;
            sum += d;
        }
        sum += xor;
        let dx = data[len];
        let ds = data[len + 1];
        let valid = data[len] == xor % 256 && data[len + 1] == sum % 256;
        if (!valid) {
            return -1;
        }

        return code;
    }

    interface Log {
        event: number;
        punchMethod?: number;
        employee?: number;
        workCode?: number;
        date?: time.Time;
        invalid: boolean;
    }

    /**
     * id is the terminal database row ID, which is not the same as the device terminalID
     */
    function downloadLogs(id: number, db: sql.DB, dev: Device, loc: time.Location): number {
        let count = 0;

        var mustClose;
        if (!dev.con) {
            dev.con = net.dial("tcp", dev.IPAddress + ":" + dev.port)
            mustClose = true;
        }
        try {
            while (true) {
                var log = getOldestLog(dev, loc);
                if (!log) {
                    break;
                }

                if (!log.employee) {
                    // ignore invalid events
                    deleteOldestLog(dev);
                    continue;
                }

                let record = {
                    employee: log.employee,
                    workState: amura.UNSET_WORKSTATE,
                    date: log.date,
                    workCode: log.workCode,
                    punchMethod: log.punchMethod,
                    terminal: id,
                    method: log.event,
                    invalid: log.invalid,
                };

                amura.insertPunchRecord(db, record);
                count++;
                deleteOldestLog(dev);
            }
        }
        finally {
            if (mustClose) {
                dev.con.close();
                dev.con = null;
            }
        }

        return count;
    }

    /**
     * Read the oldest log
     */
    function getOldestLog(dev: Device, loc: time.Location): Log {
        let buf = newExtPacket(dev.id, 0x25);
        dev.con.write(buf)
        let echo = io.read(dev.con);

        if (check(echo) == ACK) {
            // If there is no log left, the controller will echo ACK
            return null;
        }

        let event = getFunctionCode(echo);

        var log: Log = <any>{ event: event };

        let sec = getDataByte(echo, 1);
        let min = getDataByte(echo, 2);
        let hour = getDataByte(echo, 3);
        let day = getDataByte(echo, 5);
        let month = getDataByte(echo, 6);
        let y = time.now().year;
        let year = y - (y % 100) + getDataByte(echo, 7);
        log.date = time.date(year, month, day, hour, min, sec, loc);

        // the user id is made of two bytes
        log.employee = getDataByte(echo, 9) << 8 | getDataByte(echo, 10);
        log.workCode = getDataByte(echo, 25);

        switch (event) {
            case EVENT_OK_CARD:
                log.punchMethod = amura.PunchRecordPunchMethod.Card;
                log.invalid = false;
                break;

            case EVENT_OK_FINGERPRINT:
                log.punchMethod = amura.PunchRecordPunchMethod.Fingerprint;
                log.invalid = false;
                break;

            default:
                log.punchMethod = 0;
                log.invalid = true;
                log.employee = 0;
                break;
        }

        return log;
    }

    function deleteOldestLog(dev: Device) {
        let buf = newExtPacket(dev.id, 0x37);
        dev.con.write(buf)
        let echo = io.read(dev.con);
        if (check(echo) != ACK) {
            throw t("@@delete log ha fallado");
        }
    }

    /**
     * Set the device time.
     */
    function setTime(dev: Device, t: time.Time) {
        var mustClose;
        if (!dev.con) {
            dev.con = net.dial("tcp", dev.IPAddress + ":" + dev.port)
            mustClose = true;
        }
        try {
            let p = newPacket(dev.id, 0x23, [t.second, t.minute, t.hour, t.dayOfWeek + 1, t.day, t.month, t.year % 100]);
            dev.con.write(p)
            let echo = io.read(dev.con);
            if (check(echo) != ACK) {
                throw t("@@La operación ha fallado.");
            }
        }
        finally {
            if (mustClose) {
                dev.con.close();
                dev.con = null;
            }
        }
    }

    /**
     * Get the device time
     */
    function getTime(dev: Device, loc: time.Location): time.Time {
        let echo: number[] = [];

        var mustClose;
        if (!dev.con) {
            dev.con = net.dial("tcp", dev.IPAddress + ":" + dev.port)
            mustClose = true;
        }

        try {
            let p = newPacket(dev.id, 0x24);
            dev.con.write(p)
            echo = io.read(dev.con);
        }
        finally {
            if (mustClose) {
                dev.con.close();
                dev.con = null;
            }
        }

        let sec = echo[5];
        let min = echo[6];
        let hour = echo[7];
        let day = echo[9];
        let month = echo[10];
        let y = time.now().year;
        let year = y - (y % 100) + echo[11];
        return time.date(year, month, day, hour, min, sec, loc);
    }

    const TEMPLATE_SIZE = 384;
    const DOUBLE_TEMPLATE_SIZE = TEMPLATE_SIZE * 2;


    function pauseFingerprint(dev: Device) {
        let buf = newExtPacket(dev.id, 0x8F, [0x25, 0x30])
        dev.con.write(buf)
        let echo = io.read(dev.con);
        if (check(echo) != ACK) {
            throw t("@@La operación ha fallado.");
        }
    }

    function restoreFingerprint(dev: Device) {
        let buf = newExtPacket(dev.id, 0x8F, [0x25, 0x31])
        dev.con.write(buf)
        let echo = io.read(dev.con);
        if (check(echo) != ACK) {
            throw t("@@La operación ha fallado.");
        }
    }

    /**
     * Get the duser fingerprint templates. Can be 1 (384 bytes) or 2 (768)
     */
    function getFPTemplates(dev: Device, user: number): number[] {
        // user format is 4 bytes
        let ub = array.bytes(4);
        binary.putInt32BigEndian(ub, user)

        let data;
        let buf: number[];
        let echo: number[];

        // how many?
        buf = newExtPacket(dev.id, 0x8F, [0x21, ub[0], ub[1], ub[2], ub[3]])
        dev.con.write(buf)
        echo = io.read(dev.con);

        let len = echo.length;
        let count = binary.int16BigEndian(echo.getRange(len - 6, 2));

        switch (count) {
            case 0:
                break;

            case 1:
                buf = newExtPacket(dev.id, 0x8F, [0x23, ub[0], ub[1], ub[2], ub[3], 0x00, 0x00, 0x01, 0x80]);
                dev.con.write(buf)
                echo = io.read(dev.con);
                data = echo.getRange(9, echo.length - 11)
                break;

            case 2:
                buf = newExtPacket(dev.id, 0x8F, [0x23, ub[0], ub[1], ub[2], ub[3], 0x00, 0x00, 0x01, 0x80]);
                dev.con.write(buf)
                echo = io.read(dev.con);
                data = echo.getRange(9, echo.length - 11)

                buf = newExtPacket(dev.id, 0x8F, [0x23, ub[0], ub[1], ub[2], ub[3], 0x01, 0x80, 0x01, 0x80]);
                dev.con.write(buf)
                echo = io.read(dev.con);
                data = data.concat(echo.getRange(9, echo.length - 11))
                break;
        }

        return data;
    }

    function deleteFPTemplates(dev: Device, userFrom: number, userTo: number) {
        // user format is 4 bytes
        let fromB = array.bytes(4);
        let toB = array.bytes(4);
        binary.putInt32BigEndian(fromB, userFrom)
        binary.putInt32BigEndian(toB, userTo)

        let data = newExtPacket(dev.id, 0x8F, [0x22, fromB[0], fromB[1], fromB[2], fromB[3], toB[0], toB[1], toB[2], toB[3]]);
        dev.con.write(data)
        let echo = io.read(dev.con);
        if (check(echo) != ACK) {
            throw t("@@delete ha fallado.");
        }
    }

    function writeFPTemplates(dev: Device, user: number, data: number[]) {
        // user format is 4 bytes
        let userB = array.bytes(4);
        binary.putInt32BigEndian(userB, user)

        let buf: number[];
        let echo: number[];
        let fpData;

        switch (data.length) {

            case TEMPLATE_SIZE:
                fpData = [0x24, userB[0], userB[1], userB[2], userB[3], 0x01, 0x80, 0x00, 0x00, 0x01, 0x80];
                fpData = fpData.concat(data);
                buf = newExtPacket(dev.id, 0x8F, fpData);
                dev.con.write(buf)
                echo = io.read(dev.con);
                if (check(echo) != ACK) {
                    throw t("@@write ha fallado.");
                }
                break;

            case DOUBLE_TEMPLATE_SIZE:
                fpData = [0x24, userB[0], userB[1], userB[2], userB[3], 0x03, 0x00, 0x00, 0x00, 0x01, 0x80];
                fpData = fpData.concat(data.getRange(0, TEMPLATE_SIZE));
                buf = newExtPacket(dev.id, 0x8F, fpData);
                dev.con.write(buf)
                echo = io.read(dev.con);
                if (check(echo) != ACK) {
                    throw t("@@write ha fallado.");
                }

                fpData = [0x24, userB[0], userB[1], userB[2], userB[3], 0x03, 0x00, 0x01, 0x80, 0x01, 0x80];
                fpData = fpData.concat(data.getRange(TEMPLATE_SIZE + 1));
                buf = newExtPacket(dev.id, 0x8F, fpData);
                dev.con.write(buf)
                echo = io.read(dev.con);
                if (check(echo) != ACK) {
                    throw t("@@write ha fallado.");
                }
                break;

            default:
                throw "Invalid length";
        }
    }
}

// namespace soyal_tests {

//     function _testFingerprints() {
//         let dev = soyal.newDevice(1, "192.168.1.127", 1621)
//         soyal.openCon(dev);
//         let data = soyal.getFPTemplates(dev, 2);
//         soyal.deleteFPTemplates(dev, 2, 2);
//         soyal.writeFPTemplates(dev, 2, data);
//         soyal.closeCon(dev);
//     }

//     function _testLogs() {
//         let dev = soyal.newDevice(1, "192.168.1.127", 1621)
//         let db = sql.open("mysql", "root:@unix(/var/run/mysqld/mysqld.sock)/");
//         db.setDatabase("amura")
//         let loc = time.loadLocation("Europe/Madrid")
//         soyal.getOldestLog(dev, loc);
//     }

//     function testExtPacket() {
//         var got = soyal.newExtPacket(0x01, 0x18);
//         var exp = [0xFF, 0x00, 0x5A, 0xA5, 0x00, 0x04, 0x01, 0x18, 0xE6, 0xFF]
//         if (!got.equals(exp)) {
//             throw "Invalid result";
//         }
//     }

//     function testPacket() {
//         var got = soyal.newPacket(0x01, 0x18);
//         var exp = [0x7E, 0x4, 0x1, 0x18, 0xE6, 0xFF]
//         if (!got.equals(exp)) {
//             throw "Invalid result";
//         }
//     }

// }