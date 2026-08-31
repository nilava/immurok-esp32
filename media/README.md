# Media

Drop `demo.gif` here and uncomment the image line near the top of the root `README.md`.

## Making the GIF

Shoot a short video (phone is fine), then convert. Keep it **under ~10 MB** — GitHub
stops rendering larger files inline, which is the usual reason a demo silently doesn't
show up.

```bash
# Trim to the good 6 seconds, scale to 720px wide, ~12fps, with a decent palette.
ffmpeg -ss 00:00:03 -t 6 -i clip.mov \
  -vf "fps=12,scale=720:-1:flags=lanczos,split[a][b];[a]palettegen[p];[b][p]paletteuse" \
  -loop 0 demo.gif

# If it's still too big, drop to 560px or 10fps:
#   fps=10,scale=560:-1:...
ls -lh demo.gif
```

## What makes a good one

The whole value of this device is in one gesture, so show that gesture uninterrupted:
locked screen in frame, finger touches the sensor, ring goes cyan then green, screen
unlocks. One continuous shot, no cuts — cuts make people wonder what happened between
them.

Worth filming separately if you make more than one:

- **Hold to lock** — the two-second press, ring turns blue, screen locks.
- **Host switch** — touch the switch finger, ring breathes blue, the other machine picks
  it up. This is the most distinctive feature and the hardest to explain in words.
- **SSH signing** — `ssh -T git@github.com`, ring lights, touch, authenticated.

Frame the device and the screen together where you can. A shot of only the ring doesn't
show that anything happened; a shot of only the screen doesn't show why.
