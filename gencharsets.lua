
local sets = {
    {prnt = [[abcdefghijklmnopqrstuvwxyz]], len = 26},
    {prnt = [[ABCDEFGHIJKLMNOPQRSTUVWXYZ]], len = 26},
    {prnt = [[0123456789]], len = 10},
    {prnt = [[!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~]], len = 32},
}

for i = 0, (2 ^ #sets) - 1 do
    local str, len, num, used = "", 0, 0, {0, 0, 0, 0}
    for k, v in ipairs(sets) do
        if bit32.band(i, 2 ^ (k - 1)) ~= 0 then
            str = str .. v.prnt
            len = len + v.len
            num = num + 1
            used[num] = v.len
        end
    end
    print(string.format('\t{"%s", %i, %i, {%i, %i, %i, %i}},', str, len, num, unpack(used)))
end