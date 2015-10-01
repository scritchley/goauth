package goauth

import "time"

// timeNow provides a time.Now function that can be overriden in testing.
var timeNow = time.Now
