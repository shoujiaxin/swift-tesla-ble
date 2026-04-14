import SwiftProtobuf
@testable import TeslaBLE
import XCTest

final class VehicleSnapshotMapperTests: XCTestCase {
    func testEmptyVehicleDataProducesAllNils() {
        let data = CarServer_VehicleData()
        let snapshot = VehicleSnapshotMapper.map(data)
        XCTAssertNil(snapshot.charge)
        XCTAssertNil(snapshot.climate)
        XCTAssertNil(snapshot.drive)
        XCTAssertNil(snapshot.closures)
        XCTAssertNil(snapshot.tirePressure)
        XCTAssertNil(snapshot.media)
        XCTAssertNil(snapshot.mediaDetail)
        XCTAssertNil(snapshot.softwareUpdate)
        XCTAssertNil(snapshot.chargeSchedule)
        XCTAssertNil(snapshot.preconditionSchedule)
        XCTAssertNil(snapshot.parentalControls)
    }

    func testChargeStateMapping() {
        var data = CarServer_VehicleData()
        var charge = CarServer_ChargeState()
        charge.batteryLevel = 75
        charge.batteryRange = 250.5
        charge.estBatteryRange = 240.0
        charge.chargerVoltage = 240
        charge.chargerActualCurrent = 32
        charge.chargerPower = 7
        charge.chargeLimitSoc = 90
        charge.minutesToFullCharge = 120
        charge.chargeRateMph = 30
        charge.chargePortDoorOpen = true
        data.chargeState = charge

        let snapshot = VehicleSnapshotMapper.map(data)
        XCTAssertEqual(snapshot.charge?.batteryLevel, 75)
        XCTAssertEqual(snapshot.charge?.batteryRangeMiles ?? 0, Double(Float(250.5)), accuracy: 0.01)
        XCTAssertEqual(snapshot.charge?.estBatteryRangeMiles ?? 0, Double(Float(240.0)), accuracy: 0.01)
        XCTAssertEqual(snapshot.charge?.chargerVoltage, 240)
        XCTAssertEqual(snapshot.charge?.chargerCurrent, 32)
        XCTAssertEqual(snapshot.charge?.chargerPower, 7)
        XCTAssertEqual(snapshot.charge?.chargeLimitPercent, 90)
        XCTAssertEqual(snapshot.charge?.minutesToFullCharge, 120)
        XCTAssertEqual(snapshot.charge?.chargeRateMph, 30.0)
        XCTAssertEqual(snapshot.charge?.chargePortOpen, true)
    }

    func testDriveStateShiftMapping() {
        var data = CarServer_VehicleData()
        var drive = CarServer_DriveState()
        var shift = CarServer_ShiftState()
        shift.type = .d(CarServer_Void())
        drive.shiftState = shift
        drive.speedFloat = 42.0
        data.driveState = drive

        let snapshot = VehicleSnapshotMapper.map(data)
        XCTAssertEqual(snapshot.drive?.shiftState, .drive)
        XCTAssertEqual(snapshot.drive?.speedMph ?? 0, 42.0, accuracy: 0.001)
    }

    func testMapDriveOnlyReturnsDriveState() {
        var data = CarServer_VehicleData()
        var drive = CarServer_DriveState()
        var shift = CarServer_ShiftState()
        shift.type = .p(CarServer_Void())
        drive.shiftState = shift
        data.driveState = drive

        let result = VehicleSnapshotMapper.mapDrive(data)
        XCTAssertEqual(result.shiftState, .park)
    }

    func testMapDriveMissingStateReturnsEmpty() {
        let result = VehicleSnapshotMapper.mapDrive(CarServer_VehicleData())
        XCTAssertNil(result.shiftState)
        XCTAssertNil(result.speedMph)
    }

    // MARK: - ChargingStatus enum

    func testChargingStatusAllVariants() {
        let cases: [(CarServer_ChargeState.ChargingState.OneOf_Type, ChargeState.ChargingStatus?)] = [
            (.disconnected(CarServer_Void()), .disconnected),
            (.charging(CarServer_Void()), .charging),
            (.complete(CarServer_Void()), .complete),
            (.stopped(CarServer_Void()), .stopped),
            (.starting(CarServer_Void()), .starting),
            (.unknown(CarServer_Void()), .disconnected),
            (.noPower(CarServer_Void()), .disconnected),
            (.calibrating(CarServer_Void()), .disconnected),
        ]
        for (type, expected) in cases {
            var data = CarServer_VehicleData()
            var charge = CarServer_ChargeState()
            var state = CarServer_ChargeState.ChargingState()
            state.type = type
            charge.chargingState = state
            data.chargeState = charge
            let snapshot = VehicleSnapshotMapper.map(data)
            XCTAssertEqual(snapshot.charge?.chargingStatus, expected, "status=\(type)")
        }

        // type == nil → nil
        var data = CarServer_VehicleData()
        var charge = CarServer_ChargeState()
        charge.chargingState = CarServer_ChargeState.ChargingState()
        data.chargeState = charge
        XCTAssertNil(VehicleSnapshotMapper.map(data).charge?.chargingStatus)
    }

    // MARK: - Shift enum

    func testShiftAllVariants() {
        let cases: [(CarServer_ShiftState.OneOf_Type, DriveState.ShiftState?)] = [
            (.p(CarServer_Void()), .park),
            (.r(CarServer_Void()), .reverse),
            (.n(CarServer_Void()), .neutral),
            (.d(CarServer_Void()), .drive),
            (.invalid(CarServer_Void()), nil),
            (.sna(CarServer_Void()), nil),
        ]
        for (type, expected) in cases {
            var data = CarServer_VehicleData()
            var drive = CarServer_DriveState()
            var shift = CarServer_ShiftState()
            shift.type = type
            drive.shiftState = shift
            data.driveState = drive
            XCTAssertEqual(VehicleSnapshotMapper.map(data).drive?.shiftState, expected, "type=\(type)")
        }

        // type == nil → nil
        var data = CarServer_VehicleData()
        var drive = CarServer_DriveState()
        drive.shiftState = CarServer_ShiftState()
        data.driveState = drive
        XCTAssertNil(VehicleSnapshotMapper.map(data).drive?.shiftState)
    }

    // MARK: - Climate

    func testClimateStateMappingFull() {
        var data = CarServer_VehicleData()
        var climate = CarServer_ClimateState()
        climate.insideTempCelsius = 21.5
        climate.outsideTempCelsius = 10.0
        climate.driverTempSetting = 22.0
        climate.passengerTempSetting = 23.0
        climate.fanStatus = 4
        climate.isClimateOn = true
        climate.seatHeaterLeft = 2
        climate.seatHeaterRight = 1
        climate.seatHeaterRearLeft = 0
        climate.seatHeaterRearCenter = 3
        climate.seatHeaterRearRight = 2
        climate.steeringWheelHeater = true
        climate.batteryHeater = false
        climate.bioweaponModeOn = true
        var defrost = CarServer_ClimateState.DefrostMode()
        defrost.type = .normal(CarServer_Void())
        climate.defrostMode = defrost
        data.climateState = climate

        let c = VehicleSnapshotMapper.map(data).climate
        XCTAssertEqual(c?.insideTempCelsius ?? 0, 21.5, accuracy: 0.01)
        XCTAssertEqual(c?.outsideTempCelsius ?? 0, 10.0, accuracy: 0.01)
        XCTAssertEqual(c?.driverTempSettingCelsius ?? 0, 22.0, accuracy: 0.01)
        XCTAssertEqual(c?.passengerTempSettingCelsius ?? 0, 23.0, accuracy: 0.01)
        XCTAssertEqual(c?.fanStatus, 4)
        XCTAssertEqual(c?.isClimateOn, true)
        XCTAssertEqual(c?.seatHeaterFrontLeft, .medium)
        XCTAssertEqual(c?.seatHeaterFrontRight, .low)
        XCTAssertEqual(c?.seatHeaterRearLeft, .off)
        XCTAssertEqual(c?.seatHeaterRearCenter, .high)
        XCTAssertEqual(c?.seatHeaterRearRight, .medium)
        XCTAssertEqual(c?.steeringWheelHeater, true)
        XCTAssertEqual(c?.isBatteryHeaterOn, false)
        XCTAssertEqual(c?.defrostOn, true)
        XCTAssertEqual(c?.bioweaponMode, true)
    }

    func testClimateDefrostModeAllVariants() {
        let cases: [(CarServer_ClimateState.DefrostMode.OneOf_Type, Bool?)] = [
            (.off(CarServer_Void()), false),
            (.normal(CarServer_Void()), true),
            (.max(CarServer_Void()), true),
        ]
        for (type, expected) in cases {
            var data = CarServer_VehicleData()
            var climate = CarServer_ClimateState()
            var defrost = CarServer_ClimateState.DefrostMode()
            defrost.type = type
            climate.defrostMode = defrost
            data.climateState = climate
            XCTAssertEqual(VehicleSnapshotMapper.map(data).climate?.defrostOn, expected, "type=\(type)")
        }

        // type == nil → nil
        var data = CarServer_VehicleData()
        var climate = CarServer_ClimateState()
        climate.defrostMode = CarServer_ClimateState.DefrostMode()
        data.climateState = climate
        XCTAssertNil(VehicleSnapshotMapper.map(data).climate?.defrostOn)
    }

    func testClimateSeatHeaterOutOfRangeReturnsNil() {
        var data = CarServer_VehicleData()
        var climate = CarServer_ClimateState()
        climate.seatHeaterLeft = 99 // not a valid SeatHeaterLevel raw value
        data.climateState = climate
        XCTAssertNil(VehicleSnapshotMapper.map(data).climate?.seatHeaterFrontLeft)
    }

    // MARK: - Closures

    func testClosuresStateFullMapping() {
        var data = CarServer_VehicleData()
        var closures = CarServer_ClosuresState()
        closures.doorOpenDriverFront = true
        closures.doorOpenPassengerFront = false
        closures.doorOpenDriverRear = true
        closures.doorOpenPassengerRear = false
        closures.doorOpenTrunkFront = true
        closures.doorOpenTrunkRear = false
        closures.locked = true
        closures.windowOpenDriverFront = false
        closures.windowOpenPassengerFront = true
        closures.windowOpenDriverRear = false
        closures.windowOpenPassengerRear = true
        closures.sunRoofPercentOpen = 50
        closures.valetMode = false
        closures.isUserPresent = true

        var sunroof = CarServer_ClosuresState.SunRoofState()
        sunroof.type = .open(CarServer_Void())
        closures.sunRoofState = sunroof

        var sentry = CarServer_ClosuresState.SentryModeState()
        sentry.type = .armed(CarServer_Void())
        closures.sentryModeState = sentry

        data.closuresState = closures

        let c = VehicleSnapshotMapper.map(data).closures
        XCTAssertEqual(c?.frontDriverDoor, true)
        XCTAssertEqual(c?.frontPassengerDoor, false)
        XCTAssertEqual(c?.rearDriverDoor, true)
        XCTAssertEqual(c?.rearPassengerDoor, false)
        XCTAssertEqual(c?.frontTrunk, true)
        XCTAssertEqual(c?.rearTrunk, false)
        XCTAssertEqual(c?.locked, true)
        XCTAssertEqual(c?.windowDriverFront, false)
        XCTAssertEqual(c?.windowPassengerFront, true)
        XCTAssertEqual(c?.windowDriverRear, false)
        XCTAssertEqual(c?.windowPassengerRear, true)
        XCTAssertEqual(c?.sunroofState, .open)
        XCTAssertEqual(c?.sunroofPercentOpen, 50)
        XCTAssertEqual(c?.sentryModeActive, true)
        XCTAssertEqual(c?.valetMode, false)
        XCTAssertEqual(c?.isUserPresent, true)
    }

    func testSunroofStateAllVariants() {
        let cases: [(CarServer_ClosuresState.SunRoofState.OneOf_Type, ClosuresState.SunroofState?)] = [
            (.closed(CarServer_Void()), .closed),
            (.open(CarServer_Void()), .open),
            (.vent(CarServer_Void()), .vent),
            (.moving(CarServer_Void()), .moving),
            (.calibrating(CarServer_Void()), .calibrating),
            (.unknown(CarServer_Void()), .unknown),
        ]
        for (type, expected) in cases {
            var data = CarServer_VehicleData()
            var closures = CarServer_ClosuresState()
            var sunroof = CarServer_ClosuresState.SunRoofState()
            sunroof.type = type
            closures.sunRoofState = sunroof
            data.closuresState = closures
            XCTAssertEqual(VehicleSnapshotMapper.map(data).closures?.sunroofState, expected, "type=\(type)")
        }

        // type == nil → nil
        var data = CarServer_VehicleData()
        var closures = CarServer_ClosuresState()
        closures.sunRoofState = CarServer_ClosuresState.SunRoofState()
        data.closuresState = closures
        XCTAssertNil(VehicleSnapshotMapper.map(data).closures?.sunroofState)
    }

    func testSentryModeStateAllVariants() {
        let cases: [(CarServer_ClosuresState.SentryModeState.OneOf_Type, Bool?)] = [
            (.off(CarServer_Void()), false),
            (.idle(CarServer_Void()), true),
            (.armed(CarServer_Void()), true),
            (.aware(CarServer_Void()), true),
            (.panic(CarServer_Void()), true),
            (.quiet(CarServer_Void()), true),
        ]
        for (type, expected) in cases {
            var data = CarServer_VehicleData()
            var closures = CarServer_ClosuresState()
            var sentry = CarServer_ClosuresState.SentryModeState()
            sentry.type = type
            closures.sentryModeState = sentry
            data.closuresState = closures
            XCTAssertEqual(VehicleSnapshotMapper.map(data).closures?.sentryModeActive, expected, "type=\(type)")
        }

        // type == nil → nil
        var data = CarServer_VehicleData()
        var closures = CarServer_ClosuresState()
        closures.sentryModeState = CarServer_ClosuresState.SentryModeState()
        data.closuresState = closures
        XCTAssertNil(VehicleSnapshotMapper.map(data).closures?.sentryModeActive)
    }

    // MARK: - Tire pressure

    func testTirePressureStateFullMapping() {
        var data = CarServer_VehicleData()
        var tires = CarServer_TirePressureState()
        tires.tpmsPressureFl = 2.5
        tires.tpmsPressureFr = 2.6
        tires.tpmsPressureRl = 2.7
        tires.tpmsPressureRr = 2.8
        tires.tpmsSoftWarningFl = true
        tires.tpmsHardWarningFl = false
        tires.tpmsSoftWarningFr = false
        tires.tpmsHardWarningFr = false
        tires.tpmsSoftWarningRl = false
        tires.tpmsHardWarningRl = true
        tires.tpmsSoftWarningRr = false
        tires.tpmsHardWarningRr = false
        tires.tpmsRcpFrontValue = 2.4
        tires.tpmsRcpRearValue = 2.6
        data.tirePressureState = tires

        let t = VehicleSnapshotMapper.map(data).tirePressure
        XCTAssertEqual(t?.frontLeft?.pressureBar ?? 0, 2.5, accuracy: 0.01)
        XCTAssertEqual(t?.frontLeft?.hasWarning, true) // soft warn set
        XCTAssertEqual(t?.frontRight?.pressureBar ?? 0, 2.6, accuracy: 0.01)
        XCTAssertEqual(t?.frontRight?.hasWarning, false)
        XCTAssertEqual(t?.rearLeft?.hasWarning, true) // hard warn set
        XCTAssertEqual(t?.rearRight?.pressureBar ?? 0, 2.8, accuracy: 0.01)
        XCTAssertEqual(t?.recommendedColdFrontBar ?? 0, 2.4, accuracy: 0.01)
        XCTAssertEqual(t?.recommendedColdRearBar ?? 0, 2.6, accuracy: 0.01)
    }

    // MARK: - Media / MediaDetail

    func testMediaStateMapping() {
        var data = CarServer_VehicleData()
        var media = CarServer_MediaState()
        media.nowPlayingArtist = "Daft Punk"
        media.nowPlayingTitle = "Around the World"
        media.audioVolume = 6.5
        media.audioVolumeMax = 11.0
        media.remoteControlEnabled = true
        data.mediaState = media

        let m = VehicleSnapshotMapper.map(data).media
        XCTAssertEqual(m?.nowPlayingArtist, "Daft Punk")
        XCTAssertEqual(m?.nowPlayingTitle, "Around the World")
        XCTAssertEqual(m?.audioVolume ?? 0, 6.5, accuracy: 0.01)
        XCTAssertEqual(m?.audioVolumeMax ?? 0, 11.0, accuracy: 0.01)
        XCTAssertEqual(m?.remoteControlEnabled, true)
    }

    func testMediaDetailStateMapping() {
        var data = CarServer_VehicleData()
        var detail = CarServer_MediaDetailState()
        detail.nowPlayingDuration = 240
        detail.nowPlayingElapsed = 60
        detail.nowPlayingAlbum = "Discovery"
        detail.nowPlayingStation = "KEXP"
        detail.nowPlayingSourceString = "Spotify"
        detail.a2DpSourceName = "iPhone"
        data.mediaDetailState = detail

        let d = VehicleSnapshotMapper.map(data).mediaDetail
        XCTAssertEqual(d?.nowPlayingDurationSeconds, 240)
        XCTAssertEqual(d?.nowPlayingElapsedSeconds, 60)
        XCTAssertEqual(d?.nowPlayingAlbum, "Discovery")
        XCTAssertEqual(d?.nowPlayingStation, "KEXP")
        XCTAssertEqual(d?.nowPlayingSource, "Spotify")
        XCTAssertEqual(d?.a2dpSourceName, "iPhone")
    }

    // MARK: - Software update

    func testSoftwareUpdateStateMapping() {
        var data = CarServer_VehicleData()
        var update = CarServer_SoftwareUpdateState()
        update.version = "2026.4.1"
        update.downloadPerc = 75
        update.installPerc = 0
        update.expectedDurationSec = 1800
        data.softwareUpdateState = update

        let u = VehicleSnapshotMapper.map(data).softwareUpdate
        XCTAssertEqual(u?.version, "2026.4.1")
        XCTAssertEqual(u?.downloadPercent, 75)
        XCTAssertEqual(u?.installPercent, 0)
        XCTAssertEqual(u?.expectedDurationSeconds, 1800)
    }

    // MARK: - Parental controls

    func testParentalControlsMapping() {
        var data = CarServer_VehicleData()
        var pc = CarServer_ParentalControlsState()
        pc.parentalControlsActive = true
        pc.parentalControlsPinSet = false
        data.parentalControlsState = pc

        let result = VehicleSnapshotMapper.map(data).parentalControls
        XCTAssertEqual(result?.active, true)
        XCTAssertEqual(result?.pinSet, false)
    }

    // MARK: - Schedule state sentinels

    func testScheduleStateSentinelsArePresentWhenSubmessageSet() {
        var data = CarServer_VehicleData()
        data.chargeScheduleState = CarServer_ChargeScheduleState()
        data.preconditioningScheduleState = CarServer_PreconditioningScheduleState()
        let snapshot = VehicleSnapshotMapper.map(data)
        XCTAssertNotNil(snapshot.chargeSchedule)
        XCTAssertNotNil(snapshot.preconditionSchedule)
    }
}
