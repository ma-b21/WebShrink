package utils

import "testing"

func TestDecodeSysdigProcessEventFallbackToThreadTidAndEvtInfo(t *testing.T) {
	raw := []byte(`{"evt.type":"execve","evt.info":"res=0 exe=lsblk args=-O.-J.-b. tid=213265(lsblk) pid=213265(lsblk) ptid=213016(CasaOS)","proc.name":"lsblk","thread.tid":213265}`)

	event, err := DecodeSysdigProcessEvent(raw)
	if err != nil {
		t.Fatalf("DecodeSysdigProcessEvent failed: %v", err)
	}
	if event.Pid != 213265 {
		t.Fatalf("unexpected pid: got %d want %d", event.Pid, 213265)
	}
	if event.PPid != 213016 {
		t.Fatalf("unexpected ppid: got %d want %d", event.PPid, 213016)
	}
	if event.Tid != 213265 {
		t.Fatalf("unexpected tid: got %d want %d", event.Tid, 213265)
	}
	if event.Type != "execve" {
		t.Fatalf("unexpected type: got %q", event.Type)
	}
	if event.Name != "lsblk" {
		t.Fatalf("unexpected name: got %q", event.Name)
	}
}
