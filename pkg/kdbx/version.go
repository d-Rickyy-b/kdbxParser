package kdbx

import "fmt"

type Version struct {
	Minor uint16
	Major uint16
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}
