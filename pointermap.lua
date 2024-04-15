function onPointerMapGenerationStartHook()
    writeByte(0x65, 1)
end

function onPointerMapGenerationFinishHook()
    writeByte(0x65, 0)
end

onPointerMapGenerationStart = onPointerMapGenerationStartHook
onPointerMapGenerationFinish = onPointerMapGenerationFinishHook
