
/**
 * Para entrar como administrador:
 * 
 *   Pulsar: 0, OK, 12345, OK
 * 
 */
namespace anviz {
    const ACK_SUCCESS = 0x00; // operation successful
    const ACK_FAIL = 0x01; // operation failed
    const ACK_FULL = 0x04; // user full
    const ACK_EMPTY = 0x05; // user empty
    const ACK_NO_USER = 0x06; // user not exist
    const ACK_TIME_OUT = 0x08; //capture timeout
    const ACK_USER_OCCUPIED = 0x0A; //user already exists
    const ACK_FINGER_OCCUPIED = 0x0B; //fingerprint already exists

    export function newReader(id: number, ip: string, port: number): amura.Reader {
        let dev = newDevice(id, ip, port);

        return {
            getTime: (loc: time.Location) => getTime(dev, loc),
            setTime: (t: time.Time) => setTime(dev, t),
            downloadLogs: (id: number, db: sql.DB, loc: time.Location) => downloadLogs(id, db, dev, loc),
            downloadUsers: (db: sql.DB) => downloadusers(db, dev),
            uploadUsers: (db: sql.DB, users: number[]) => uploadusers(db, dev, users),
            deleteAllUsers: () => deleteAllUsers(dev)
        }
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

    function deleteAllUsers(dev: Device) {
        var mustClose;
        if (!dev.con) {
            dev.con = net.dial("tcp", dev.IPAddress + ":" + dev.port)
            mustClose = true;
        }
        try {
            let p = newPacket(dev.id, 0x4D);
            dev.con.write(p)

            let response = io.read(dev.con);
            if (response.length != 11) {
                throw "Invalid response length: " + response.length;
            }

            if (response[5] != 0xCD) {
                throw "No ACK";
            }

            if (response[6] != ACK_SUCCESS) {
                throw "No SUCCESS"
            }

            let len = response.length;
            let crc = CRC16(response.getRange(0, len - 2));
            if (crc[0] != response[len - 2] || crc[1] != response[len - 1]) {
                throw "Invalid CRC"
            }
        }
        finally {
            if (mustClose) {
                dev.con.close();
                dev.con = null;
            }
        }
    }

    function uploadusers(db: sql.DB, dev: Device, users: number[]): number {
        let count = 0;

        let employees = amura.loadEmployees(db, "WHERE a.id in (" + users.join(",") + ")").rows.select(t => t);
        let fps = amura.loadTerminalBioDatas(db, "model=? AND employee in (" + users.join(",") + ")", amura.TerminalBioDataModel.Anviz);

        var mustClose;
        if (!dev.con) {
            dev.con = net.dial("tcp", dev.IPAddress + ":" + dev.port)
            mustClose = true;
        }

        try {
            while (employees.length > 0) {
                let group = employees.length < 12 ? employees : employees.getRange(0, 12);
                let len = group.length;
                let data = [len];

                for (var employee of group) {
                    let buf = array.bytes(27);

                    // set all to 0xFF by default
                    for (var i = 0, l = buf.length; i < l; i++) {
                        buf[i] = 0xFF;
                    }

                    // userID is 5 bytes
                    let id = employee.id;
                    buf[0] = (id >> 32) & ((1 << 8) - 1)
                    buf[1] = (id >> 24) & ((1 << 8) - 1)
                    buf[2] = (id >> 16) & ((1 << 8) - 1)
                    buf[3] = (id >> 8) & ((1 << 8) - 1)
                    buf[4] = (id >> 0) & ((1 << 8) - 1)

                    // password is 3 bytes. The first 4 bits of the 1 byte is the number of digits
                    if (employee.devicePassword) {
                        let pwd = convert.toInt(employee.devicePassword);
                        buf[5] = (pwd >> 16) & ((1 << 8) - 1)
                        // set the first 4 bits and leave the other 4.
                        buf[5] = ((employee.devicePassword.length & 0xFF) << 4) | (buf[5] & 0xFF);

                        buf[6] = (pwd >> 8) & ((1 << 8) - 1)
                        buf[7] = (pwd >> 0) & ((1 << 8) - 1)
                    }
                    console.log(employee.id, employee.name)
                    if (employee.card) {
                        try {
                            let card = convert.toInt(employee.card);
                            buf[8] = (card >> 16) & ((1 << 8) - 1)
                            buf[9] = (card >> 8) & ((1 << 8) - 1)
                            buf[10] = (card >> 0) & ((1 << 8) - 1)
                        }
                        catch (e) {
                            throw { message: t("@@Tarjeta inválida para " + employee.name) }
                        }
                    }

                    data = data.concat(buf);
                }

                let p = newPacket(dev.id, 0x43, data);
                dev.con.write(p)
                let echo = io.read(dev.con);

                if (echo[5] != 0xC3) {
                    throw "No ACK";
                }

                if (echo[6] != ACK_SUCCESS) {
                    throw "No SUCCESS"
                }

                let respLen = echo.length;
                let crc = CRC16(echo.getRange(0, respLen - 2));
                if (crc[0] != echo[respLen - 2] || crc[1] != echo[respLen - 1]) {
                    throw "Invalid CRC"
                }

                // remove the ones uploaded
                employees = employees.getRange(len);
            }


            // upload fingerprints
            for (var fp of fps) {
                let buf = array.bytes(6);

                // userID is 5 bytes
                let id = fp.employee;
                buf[0] = (id >> 32) & ((1 << 8) - 1)
                buf[1] = (id >> 24) & ((1 << 8) - 1)
                buf[2] = (id >> 16) & ((1 << 8) - 1)
                buf[3] = (id >> 8) & ((1 << 8) - 1)
                buf[4] = (id >> 0) & ((1 << 8) - 1)

                // for now we are uploading just one fingerprint
                buf[5] = fp.backupCode;

                buf = buf.concat(convert.toBytes(fp.data))

                let p = newPacket(dev.id, 0x45, buf);
                dev.con.write(p)
                let echo = io.read(dev.con);

                if (echo[5] != 0xC5) {
                    throw "No ACK";
                }

                if (echo[6] != ACK_SUCCESS) {
                    throw "No SUCCESS"
                }

                let respLen = echo.length;
                let crc = CRC16(echo.getRange(0, respLen - 2));
                if (crc[0] != echo[respLen - 2] || crc[1] != echo[respLen - 1]) {
                    throw "Invalid CRC"
                }
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

    function downloadusers(db: sql.DB, dev: Device): number {
        let count = 0;
        let echo: number[] = [];

        var mustClose;
        if (!dev.con) {
            dev.con = net.dial("tcp", dev.IPAddress + ":" + dev.port)
            mustClose = true;
        }

        let users: any[] = [];

        let first = true;
        try {
            while (true) {
                let b = first ? 1 : 0;
                let p = newPacket(dev.id, 0x42, [b, 0x12]);
                dev.con.write(p)
                echo = io.read(dev.con);

                if (echo[5] != 0xC2) {
                    throw "No ACK";
                }

                if (echo[6] != ACK_SUCCESS) {
                    throw "No SUCCESS"
                }

                let respLen = echo.length;
                let crc = CRC16(echo.getRange(0, respLen - 2));
                if (crc[0] != echo[respLen - 2] || crc[1] != echo[respLen - 1]) {
                    throw "Invalid CRC"
                }

                // data length is made of 2 bytes
                let len = ((echo[7] & 0xFF) << 8) | (echo[8] & 0xFF);

                let validRecords = echo[9];

                if (validRecords == 0) {
                    break;
                }

                for (var i = 0; i < validRecords; i++) {
                    let start = 10 + (i * 30);

                    let u1 = echo[start + 1]
                    let u2 = echo[start + 2]
                    let u3 = echo[start + 3]
                    let u4 = echo[start + 4]
                    let userCode = ((u1 & 0xFF) << 24) | ((u2 & 0xFF) << 16) | ((u3 & 0xFF) << 8) | (u4 & 0xFF);

                    let remaining = len - start;
                    if (remaining > 30) {
                        remaining = 30
                    }

                    if (remaining < 0) {
                        continue;
                    }

                    //hexLog(echo.getRange(start, remaining))

                    let p1 = echo[start + 5];
                    // The first 4 bits of this byte are the number of digits in the password
                    let numPwdChars = echo[start + 5] >> 4;
                    // The last 4 bits are the start of the password. clear the HIGH 4 bits
                    p1 = p1 & ~(1 << 4);
                    p1 = p1 & ~(1 << 5);
                    p1 = p1 & ~(1 << 6);
                    p1 = p1 & ~(1 << 7);
                    let p2 = echo[start + 6];
                    let p3 = echo[start + 7];

                    let pwd;
                    if (p3 != 0xFF) {
                        pwd = ((p1 & 0xFF) << 16) | ((p2 & 0xFF) << 8) | (p3 & 0xFF);
                    }

                    let c1 = echo[start + 8];
                    let c2 = echo[start + 9];
                    let c3 = echo[start + 10];
                    let card;
                    if (c1 != 0xFF && c2 != 0xFF && c3 != 0xFF) {
                        card = ((c1 & 0xFF) << 16) | ((c2 & 0xFF) << 8) | (c3 & 0xFF);
                    }

                    users.push({ id: userCode, password: pwd, card: card })
                    count++;
                }

                first = false;
            }

            for (var user of users) {
                user.fp1 = downloadFingerPrint(dev, user.id, 1);
                user.fp2 = downloadFingerPrint(dev, user.id, 2);
            }

            db.beginTransaction();

            for (var user of users) {
                let employee = amura.loadEmployeeByID(db, user.id);
                if (!employee) {
                    amura.insertEmployee(db, {
                        id: user.id,
                        name: t("@@Empleado") + " " + user.id,
                        devicePassword: user.devicePassword,
                        card: user.card
                    })
                } else {
                    employee.devicePassword = user.devicePassword;
                    employee.card = user.card;
                    amura.updateEmployee(db, employee);
                }

                if (user.fp1 || user.fp2) {
                    db.exec("UPDATE terminalbiodata SET deleted=true WHERE employee=? AND model=?",
                        user.id, amura.TerminalBioDataModel.Anviz);
                }

                if (user.fp1) {
                    amura.insertTerminalBioData(db, {
                        employee: user.id,
                        model: amura.TerminalBioDataModel.Anviz,
                        data: user.fp1,
                        backupCode: 1
                    })
                }

                if (user.fp2) {
                    amura.insertTerminalBioData(db, {
                        employee: user.id,
                        model: amura.TerminalBioDataModel.Anviz,
                        data: user.fp2,
                        backupCode: 2
                    })
                }
            }

            db.commit();
        }
        catch (e) {
            db.rollback();
            throw e;
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
     * backupCode: the fingerprint (1 or 2).
     */
    function downloadFingerPrint(dev: Device, user: number, backupCode: number): number[] {
        let buf = array.bytes(6);

        // 5 bytes for the user
        buf[0] = (user >> 32) & ((1 << 8) - 1)
        buf[1] = (user >> 24) & ((1 << 8) - 1)
        buf[2] = (user >> 16) & ((1 << 8) - 1)
        buf[3] = (user >> 8) & ((1 << 8) - 1)
        buf[4] = (user >> 0) & ((1 << 8) - 1)

        // backup code
        buf[5] = backupCode;

        let p = newPacket(dev.id, 0x44, buf);
        dev.con.write(p)
        let echo = io.read(dev.con);

        if (echo[5] != 0xC4) {
            throw "No ACK";
        }

        if (echo[6] != ACK_SUCCESS) {
            // the user has no fingerprints registered
            return;
        }

        let respLen = echo.length;
        let crc = CRC16(echo.getRange(0, respLen - 2));
        if (crc[0] != echo[respLen - 2] || crc[1] != echo[respLen - 1]) {
            throw "Invalid CRC"
        }

        let data = echo.getRange(9, 338);
        return data;
    }

    /**
     * id is the terminal database row ID, which is not the same as the device terminalID
     */
    function downloadLogs(id: number, db: sql.DB, dev: Device, loc: time.Location): number {
        let count = 0;
        let echo: number[] = [];

        var mustClose;
        if (!dev.con) {
            dev.con = net.dial("tcp", dev.IPAddress + ":" + dev.port)
            mustClose = true;
        }

        let first = true;

        db.beginTransaction();
        try {
            while (true) {
                let b = first ? 1 : 0;
                let p = newPacket(dev.id, 0x40, [b, 0x19]);
                dev.con.write(p)
                echo = io.read(dev.con);

                if (echo[5] != 0xC0) {
                    throw "No ACK";
                }

                if (echo[6] != ACK_SUCCESS) {
                    throw "No SUCCESS"
                }

                let respLen = echo.length;
                let crc = CRC16(echo.getRange(0, respLen - 2));
                if (crc[0] != echo[respLen - 2] || crc[1] != echo[respLen - 1]) {
                    throw "Invalid CRC"
                }

                // data length is made of 2 bytes
                let len = ((echo[7] & 0xFF) << 8) | (echo[8] & 0xFF);

                let validRecords = echo[9];

                if (validRecords == 0) {
                    break;
                }

                for (var i = 0; i < validRecords; i++) {
                    let start = 10 + (i * 14);

                    let u1 = echo[start + 1]
                    let u2 = echo[start + 2]
                    let u3 = echo[start + 3]
                    let u4 = echo[start + 4]
                    let userCode = ((u1 & 0xFF) << 24) | ((u2 & 0xFF) << 16) | ((u3 & 0xFF) << 8) | (u4 & 0xFF);

                    let d1 = echo[start + 5]
                    let d2 = echo[start + 6]
                    let d3 = echo[start + 7]
                    let d4 = echo[start + 8]
                    let secs = ((d1 & 0xFF) << 24) | ((d2 & 0xFF) << 16) | ((d3 & 0xFF) << 8) | (d4 & 0xFF);
                    // documentation says from 1/1/2000 but it's actually 1/2/2000
                    let date = time.date(2000, 1, 2, 0, 0, 0, loc).addSeconds(secs);


                    let method = echo[start + 9];
                    switch (method) {
                        case 0:
                        case 1:
                            method = 1; // amura.PunchRecordPunchMethod.Fingerprint;
                            break;

                        case 2:
                            method = 2; // amura.PunchRecordPunchMethod.Pin;
                            break;

                        case 3:
                        case 8:
                            method = 3; // amura.PunchRecordPunchMethod.Card;
                            break;

                        default:
                            method = 0;
                    }

                    let t1 = echo[start + 11]
                    let t2 = echo[start + 12]
                    let t3 = echo[start + 13]
                    let workCode = ((t1 & 0xFF) << 16) | ((t2 & 0xFF) << 8) | (t3 & 0xFF);

                    var record = {
                        employee: userCode,
                        workState: amura.UNSET_WORKSTATE,
                        date: date,
                        workCode: workCode,
                        punchMethod: method,
                        terminal: id,
                        invalid: false,
                    }

                    amura.insertPunchRecord(db, record);
                    count++;

                    // console.log(log.employee, log.punchMethod, log.workCode, log.date)
                    //hexLog(response.getRange(start, 14))
                }

                first = false;
            }

            deleteLogs(dev);
            db.commit();
        }
        catch (e) {
            db.rollback();
            throw e;
        }
        finally {
            if (mustClose) {
                dev.con.close();
                dev.con = null;
            }
        }

        return count;
    }

    function deleteLogs(dev: Device) {
        let p = newPacket(dev.id, 0x4E, [0x00, 0x00, 0x00, 0x00]);
        dev.con.write(p)
        let response = io.read(dev.con);

        if (response[5] != 0xCE) {
            throw "No ACK";
        }

        if (response[6] != ACK_SUCCESS) {
            throw "No SUCCESS"
        }
    }

    /**
     * Get the device time
     */
    function getTime(dev: Device, loc: time.Location): time.Time {
        let response: number[] = [];

        var mustClose;
        if (!dev.con) {
            dev.con = net.dial("tcp", dev.IPAddress + ":" + dev.port)
            mustClose = true;
        }

        try {
            let p = newPacket(dev.id, 0x38);
            dev.con.write(p)
            response = io.read(dev.con);
        }
        finally {
            if (mustClose) {
                dev.con.close();
                dev.con = null;
            }
        }

        if (response.length != 17) {
            throw "Invalid response length";
        }

        if (response[5] != 0xB8) {
            throw "No ACK";
        }

        if (response[6] != ACK_SUCCESS) {
            throw "No SUCCESS"
        }

        let len = response.length;
        let crc = CRC16(response.getRange(0, len - 2));
        if (crc[0] != response[len - 2] || crc[1] != response[len - 1]) {
            throw "Invalid CRC"
        }

        let sec = response[14];
        let min = response[13];
        let hour = response[12];
        let day = response[11];
        let month = response[10];
        let year = response[9];

        return time.date(year % 100 + 2000, month, day, hour, min, sec, loc);
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
            let p = newPacket(dev.id, 0x39, [t.year % 100, t.month, t.day, t.hour, t.minute, t.second]);
            dev.con.write(p)

            let response = io.read(dev.con);
            if (response.length != 11) {
                throw "Invalid response length: " + response.length;
            }

            if (response[5] != 0xB9) {
                throw "No ACK";
            }

            if (response[6] != ACK_SUCCESS) {
                throw "No SUCCESS"
            }

            let len = response.length;
            let crc = CRC16(response.getRange(0, len - 2));
            if (crc[0] != response[len - 2] || crc[1] != response[len - 1]) {
                throw "Invalid CRC"
            }
        }
        finally {
            if (mustClose) {
                dev.con.close();
                dev.con = null;
            }
        }
    }

    function newPacket(deviceID: number, command: number, data?: number[]): number[] {
        let a = deviceID & ((1 << 8) - 1)
        let b = (deviceID >> 8) & ((1 << 8) - 1)
        let c = (deviceID >> 16) & ((1 << 8) - 1)
        let d = (deviceID >> 24) & ((1 << 8) - 1)


        let len = data ? data.length : 0;
        let lenHigh = (len >> 8) & ((1 << 8) - 1)
        let lenLow = len & ((1 << 8) - 1)

        let buf = [0xA5, d, c, b, a, command, lenHigh, lenLow];

        if (data) {
            buf = buf.concat(data)
        }

        let crc = CRC16(buf);
        buf = buf.concat(crc);

        return buf;
    }

    // See:
    // https://github.com/benperiton/anviz-protocol/blob/master/Src/Node/lib/Anviz/crc.js
    // http://stackoverflow.com/questions/18929423/whats-the-checksum-algorithm-for-anviz-devices/24754362#24754362
    function CRC16(buf: number[]): number[] {
        let crc = 0xFFFF;

        for (var i = 0, l = buf.length; i < l; i++) {
            crc = crc ^ buf[i];
            crc = (crc >> 8) ^ crcTable[crc & 255];
        }

        let high = (crc >> 8) & ((1 << 8) - 1)
        let low = crc & ((1 << 8) - 1)

        return [low, high];
    }

    let crcTable = [
        0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF, 0x8C48, 0x9DC1,
        0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7, 0x1081, 0x0108, 0x3393, 0x221A,
        0x56A5, 0x472C, 0x75B7, 0x643E, 0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64,
        0xF9FF, 0xE876, 0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
        0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5, 0x3183, 0x200A,
        0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C, 0xBDCB, 0xAC42, 0x9ED9, 0x8F50,
        0xFBEF, 0xEA66, 0xD8FD, 0xC974, 0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9,
        0x2732, 0x36BB, 0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
        0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A, 0xDECD, 0xCF44,
        0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72, 0x6306, 0x728F, 0x4014, 0x519D,
        0x2522, 0x34AB, 0x0630, 0x17B9, 0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3,
        0x8A78, 0x9BF1, 0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
        0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70, 0x8408, 0x9581,
        0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7, 0x0840, 0x19C9, 0x2B52, 0x3ADB,
        0x4E64, 0x5FED, 0x6D76, 0x7CFF, 0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324,
        0xF1BF, 0xE036, 0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
        0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5, 0x2942, 0x38CB,
        0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD, 0xB58B, 0xA402, 0x9699, 0x8710,
        0xF3AF, 0xE226, 0xD0BD, 0xC134, 0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E,
        0x5CF5, 0x4D7C, 0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
        0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB, 0xD68D, 0xC704,
        0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232, 0x5AC5, 0x4B4C, 0x79D7, 0x685E,
        0x1CE1, 0x0D68, 0x3FF3, 0x2E7A, 0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3,
        0x8238, 0x93B1, 0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
        0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330, 0x7BC7, 0x6A4E,
        0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
    ];
}

namespace anviz_tests {

    // function testDownloadUsers() {
    //     let r = amura.newReader(amura.TerminalModel.Anviz, 1, "192.168.1.218", 5010);
    //     r.deleteAllUsers();
    //     //     // let db = sql.openMemoryDB();
    //     //     // amura.createEmployeeTable(db);
    //     //     // amura.createTerminalBioDataTable(db);
    //     //     // r.downloadUsers(db);
    // }

    //     function testCRC16() {
    //         let crc = amura.CRC16([0xA5, 0x00, 0x00, 0x00, 0x01, 0x32, 0x00, 0x00])
    //         if (crc[0] != 0x52 || crc[1] != 0xB9) {
    //             return strings.format("Invalid CRC. Expected [52 B9], got %X", crc)
    //         }
    //     }

    // function testLogs() {
    //     let r = amura.newReader(amura.TerminalModel.Anviz, 1, "192.168.1.218", 5010);
    //     let db = sql.openMemoryDB();
    //     amura.createPunchRecordTable(db)
    //     r.downloadLogs(1, db, time.local())
    // }

    // function testTime() {
    //     let r = amura.newReader(amura.TerminalModel.Anviz, 1, "192.168.1.218", 5010);
    //     let t = r.getTime(time.local())
    //     console.log(t);
    // }
}