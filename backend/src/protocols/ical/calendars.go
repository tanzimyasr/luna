package ical

import (
	"encoding/json"
	"luna-backend/crypto"
	"luna-backend/errors"
	common "luna-backend/protocols/internal"
	"luna-backend/types"
	"net/http"
	"time"

	"github.com/emersion/go-ical"
)

type IcalCalendar struct {
	name         string
	desc         string
	color        *types.Color
	overridden   bool
	settings     *IcalCalendarSettings
	source       *IcalSource
	icalCalendar *ical.Calendar
}

type IcalCalendarSettings struct {
}

func (source *IcalSource) calendarFromIcal(rawCalendar *ical.Calendar) (*IcalCalendar, *errors.ErrorTrace) {
	name := rawCalendar.Props.Get(ical.PropName)
	if name == nil {
		name = rawCalendar.Props.Get("X-WR-CALNAME")
	}
	if name == nil {
		name = ical.NewProp(ical.PropName)
		name.SetText(source.name)
	}

	desc := rawCalendar.Props.Get(ical.PropDescription)
	if desc == nil {
		desc = rawCalendar.Props.Get("X-WR-CALDESC")
	}
	if desc == nil {
		desc = ical.NewProp(ical.PropDescription)
		desc.SetText("")
	}

	var calColor *types.Color = nil
	colProp := rawCalendar.Props.Get(ical.PropColor)
	if colProp != nil {
		var err error
		calColor, err = types.ParseColor(colProp.Value)
		if err != nil {
			calColor = nil
		}
	}

	settings := &IcalCalendarSettings{}

	calendar := &IcalCalendar{
		name:         common.UnespaceIcalString(name.Value),
		desc:         common.UnespaceIcalString(desc.Value),
		color:        calColor,
		overridden:   false,
		settings:     settings,
		source:       source,
		icalCalendar: rawCalendar,
	}

	return calendar, nil
}

func (settings *IcalCalendarSettings) Bytes() []byte {
	bytes, err := json.Marshal(settings)
	if err != nil {
		panic(err)
	}
	return bytes
}

func genCalId(sourceId types.ID, uid string) types.ID {
	return crypto.DeriveID(sourceId, uid)
}

func (calendar *IcalCalendar) GetId() types.ID {
	// ical files only have a single calendar, so they sometimes don't come with a unique ID
	return genCalId(calendar.source.id, "calendar")
}

func (calendar *IcalCalendar) GetName() string {
	return calendar.name
}

func (calendar *IcalCalendar) SetName(name string) {
	calendar.name = name
}

func (calendar *IcalCalendar) GetDesc() string {
	return calendar.desc
}

func (calendar *IcalCalendar) SetDesc(desc string) {
	calendar.desc = desc
}

func (calendar *IcalCalendar) GetSource() types.Source {
	return calendar.source
}

func (calendar *IcalCalendar) GetSettings() types.CalendarSettings {
	return calendar.settings
}

func (calendar *IcalCalendar) GetColor() *types.Color {
	if calendar.color == nil {
		return types.ColorEmpty
	} else {
		return calendar.color
	}
}

func (calendar *IcalCalendar) SetColor(color *types.Color) {
	calendar.color = color
}

func (calendar *IcalCalendar) GetOverridden() bool {
	return calendar.overridden
}

func (calendar *IcalCalendar) SetOverridden(overridden bool) {
	calendar.overridden = overridden
}

func (calendar *IcalCalendar) GetEvents(start time.Time, end time.Time, q types.DatabaseQueries) ([]types.Event, *errors.ErrorTrace) {
	res := make([]types.Event, len(calendar.icalCalendar.Children))

	count := 0
	for _, comp := range calendar.icalCalendar.Children {
		if comp.Name != "VEVENT" {
			continue
		}

		event, err := calendar.eventFromIcal(&comp.Props)
		if err != nil {
			return nil, err.
				Append(errors.LvlDebug, "Could not parse event from calendar %v (%v)", calendar.GetName(), calendar.GetId()).
				AltStr(errors.LvlWordy, "Could not parse event from calendar %v", calendar.GetId()).
				Append(errors.LvlDebug, "Could not get events from calendar %v (%v)", calendar.GetName(), calendar.GetId()).
				AltStr(errors.LvlPlain, "Could not get events from calendar %v", calendar.GetName())
		}

		if !event.GetDate().Recurrence().Repeats() && (event.GetDate().Start().Before(start) || event.GetDate().End().After(end)) {
			continue
		}
		res[count] = event
		count++
	}

	return res[:count], nil
}

func (calendar *IcalCalendar) GetEvent(settings types.EventSettings, q types.DatabaseQueries) (types.Event, *errors.ErrorTrace) {
	icalSettings := settings.(*IcalEventSettings)
	targetUid := icalSettings.Uid

	for _, comp := range calendar.icalCalendar.Children {
		if comp.Name != "VEVENT" {
			continue
		}

		event, err := calendar.eventFromIcal(&comp.Props)
		if err != nil {
			return nil, err.
				Append(errors.LvlDebug, "Could not parse event %v in calendar %v (%v)", icalSettings.Uid, calendar.GetName(), calendar.GetId()).
				AltStr(errors.LvlWordy, "Could not parse event %v in calendar %v", icalSettings.Uid, calendar.GetName()).
				Append(errors.LvlDebug, "Could not get event in calendar %v (%v)", calendar.GetName(), calendar.GetId()).
				AltStr(errors.LvlPlain, "Could not get event in calendar %v", calendar.GetName())
		}

		if event.GetSettings().(*IcalEventSettings).Uid == targetUid {
			return event, nil
		}
	}

	return nil, errors.New().Status(http.StatusNotFound).
		Append(errors.LvlWordy, "Event %v not found", icalSettings.Uid).
		AltStr(errors.LvlPlain, "Event not found")
}

/* Ical calendar is read-only */

func (calendar *IcalCalendar) AddEvent(name string, desc string, color *types.Color, date *types.EventDate, q types.DatabaseQueries) (types.Event, *errors.ErrorTrace) {
	return nil, errors.New().Status(http.StatusMethodNotAllowed)
}

func (calendar *IcalCalendar) EditEvent(event types.Event, name string, desc string, color *types.Color, date *types.EventDate, override bool, q types.DatabaseQueries) (types.Event, *errors.ErrorTrace) {
	if override {
		anyOverrides := false
		if name != "" {
			event.SetName(name)
			anyOverrides = true
		}
		if desc != "" {
			event.SetDesc(desc)
			anyOverrides = true
		}
		if color != nil && !color.IsEmpty() {
			event.SetColor(color)
			anyOverrides = true
		}

		if anyOverrides {
			q.SetEventOverrides(event.GetId(), name, desc, color)
			return event, nil
		} else {
			q.DeleteEventOverrides(event.GetId())
			return calendar.GetEvent(event.GetSettings(), q)
		}
	} else {
		return nil, errors.New().Status(http.StatusMethodNotAllowed)
	}
}

func (calendar *IcalCalendar) DeleteEvent(event types.Event, q types.DatabaseQueries) *errors.ErrorTrace {
	return errors.New().Status(http.StatusMethodNotAllowed)
}
