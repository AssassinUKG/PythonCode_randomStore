#!/usr/bin/env python3

import cairo
from math import pi

crit = 1
high = 1
medium = 2
low = 3
info = 1

# total: 10
# 1 / 10 *360 = 36
# 1 / 10 *360 = 36
# 2 / 10 *360 = 72
# 3 / 10 *360 = 108
# 3 / 10 *360 = 108

# RGB values
# crit: 229,71,97
# high: 7,45,64
# medium: 246,162,72
# Low: 112,162,136
# Info: 0,176,240


def getSegment():

    pass


def getPercent(num, total):
    return (num / total * 360)


def convertRGBColor(R, G, B):
    try:
        R_ = float(R) / 255
        G_ = float(G) / 255
        B_ = float(B) / 255
        return R_, G_, B_
    except:
        print("Could not parse RGB")
        return None


def getColorforvuln(name):

    if name == "critical":
        r, g, b = convertRGBColor("229", "71", "97")
        return r, g, b, 1
    if name == "high":
        r, g, b = convertRGBColor("7", "45", "64")
        return r, g, b, 1
    if name == "medium":
        r, g, b = convertRGBColor("246", "162", "72")
        return r, g, b, 1
    if name == "low":
        r, g, b = convertRGBColor("112", "162", "136")
        return r, g, b, 1
    if name == "info":
        r, g, b = convertRGBColor("0", "176", "240")
        return r, g, b, 1


def draw_segment(cr, a1, a2, rating):
    xc = 0.5
    yc = 0.5
    radius = 0.49
    angle1 = a1 * (pi / 180.0)  # angles are specified
    angle2 = a2 * (pi / 180.0)  # in radians

    r, g, b, a = getColorforvuln(rating)
    cr.set_source_rgba(r, g, b, a)
    # cr.set_source_rgb(r,g,b)
    cr.line_to(xc, yc)
    cr.arc(xc, yc, radius, angle1, angle2)
    cr.line_to(yc, xc)
    cr.fill()
    cr.stroke()

    print(f"R:{r}, G:{g}, B:{b}")


def path_ellipse(cr, x, y, width, height, angle=0):
    """
    x      - center x
    y      - center y
    width  - width of ellipse  (in x direction when angle=0)
    height - height of ellipse (in y direction when angle=0)
    angle  - angle in radians to rotate, clockwise
    """
    cr.save()
    cr.translate(x, y)
    cr.rotate(angle)
    cr.scale(width / 2.0, height / 2.0)
    cr.arc(0.0, 0.0, 1.0, 0.0, 2.0 * pi)
    cr.restore()


def draw_pieChart(stats):
    # stats will be str:int
    totalVuln = 0
    for s in stats:
        totalVuln += int(stats[s])
    # Get percent of all values

    CriticialPercent = getPercent(int(stats["critical"]), totalVuln)
    HighPercent = getPercent(int(stats["high"]), totalVuln)
    MediumPercent = getPercent(int(stats["medium"]), totalVuln)
    LowPercent = getPercent(int(stats["low"]), totalVuln)
    InfoPercent = getPercent(int(stats["info"]), totalVuln)

    t = CriticialPercent + HighPercent + MediumPercent + LowPercent + InfoPercent
    print()
    print(f"crit: {CriticialPercent}, high: {HighPercent}, med: {MediumPercent}, low: {LowPercent}, info: {InfoPercent}")
    print(f"Total: {t}")
    print()

    stats['critical'] = CriticialPercent
    stats['high'] = HighPercent
    stats['medium'] = MediumPercent
    stats['low'] = LowPercent
    stats['info'] = InfoPercent

    with cairo.SVGSurface("test.svg", 200, 200) as surface:
        context = cairo.Context(surface)

        context.scale(200, 200)
        cp_x, cp_y = 0.5, 0.5
        width = 0.99
        height = 0.99

        # Base Circle
        path_ellipse(context, cp_x, cp_y, width, height, pi / 2.0)
        context.set_line_width(0.01)
        context.set_source_rgba(0, 0, 0, 1)
        context.fill()

        lastPoint = 0
        for stat in stats:
            statPoint = stats[stat]
            start = lastPoint
            end = statPoint+start

            draw_segment(context, start, end, stat)
            lastPoint += statPoint


#inputVars = {"critical":"1","high":"1","medium":"1","low":"1", "info":"1"}
#inputVars = {"critical":"0","high":"0","medium":"0","low":"0", "info":"4"}

inputVars = {"critical": "6", "high": "2",
             "medium": "3", "low": "6", "info": "1"}

draw_pieChart(inputVars)


print("File Saved")
