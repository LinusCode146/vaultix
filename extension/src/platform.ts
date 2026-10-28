/** How the app unlocks without the master password on this system ("touchId" in messages means either). */
export const unlockWith = /Windows/.test(navigator.userAgent) ? "Windows Hello" : "Touch ID";

/** "Mac" or "computer". */
export const computer = /Mac/.test(navigator.userAgent) ? "Mac" : "computer";
