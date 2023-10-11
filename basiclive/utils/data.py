import itertools
from datetime import datetime
import json

def parse_frames(frame_string):
    frames = []
    if frame_string:
        try:
            frames = json.loads(frame_string.replace('\'', '\"'))
        except ValueError:
            for w in frame_string.split(','):
                v = list(map(int, w.split('-')))
                if len(v) == 2:
                    frames.extend(range(v[0], v[1] + 1))
                elif len(v) == 1:
                    frames.extend(v)
    return frames


def frame_ranges(frame_list):
    if len(frame_list):
        if isinstance(frame_list[0][1], str):
            try:
                for a, b in itertools.groupby(enumerate(frame_list), lambda xy: datetime.strptime(xy.split('.')[0], "%Y-%m-%dt%H-%M-%S%z")):
                    b = list(b)
                    yield b[0][1], b[-1][1]
            except:
                yield (0, frame_list[0]), (len(frame_list), frame_list[-1])
    else:
        for a, b in itertools.groupby(enumerate(frame_list), lambda xy: xy[1] - xy[0]):
            b = list(b)
            yield b[0][1], b[-1][1]