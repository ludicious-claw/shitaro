local lib = loadstring(game:HttpGet("https://raw.githubusercontent.com/ludicious-claw/shitaro/refs/heads/main/shitaroebet.lua"))()

if not lib then
	error("shitaroebet не загрузилась")
end

--------------------------------------------------------------------------
-- 2. ОКНО
--------------------------------------------------------------------------

local win = lib:window({
	bind = "Insert", -- клавиша открытия/закрытия
})

-- win:toggle()          -- показать/скрыть
-- win:setbind("End")    -- сменить бинд
-- if type(win.setfury) == "function" then win:setfury(true) end

local function toast(title, text, life)
	lib:notify({
		title = title or "UI",
		text = text or "",
		icon = "info",
		life = life or 4,
	})
end

toast("Готово", "библиотека загружена", 4)

--------------------------------------------------------------------------
-- 3. ВКЛАДКИ И СЕКЦИИ
--------------------------------------------------------------------------

local tabMain = win:tab({ name = "main", icon = "circle-dot", tip = "основные настройки" })
local tabExt = win:tab({ name = "extra", icon = "globe", tip = "дополнительно" })

local left = tabMain:section({ name = "features", side = "left" })
local right = tabMain:section({ name = "tuning", side = "right" })
local extLeft = tabExt:section({ name = "extra", side = "left" })

--------------------------------------------------------------------------
-- 4. ЭЛЕМЕНТЫ
--------------------------------------------------------------------------

-- toggle + вложенная группа options
local feature = left:toggle({
	name = "my feature",
	default = false,
	options = true, -- ОБЯЗАТЕЛЬНО, иначе feature.options == nil
	flag = "MyFeature",
	callback = function(v)
		print("feature =", v)
	end,
})

-- feature.options — это ГОТОВАЯ секция, вызываем её методы напрямую
-- (:section() на ней не существует)
local opt = feature.options
if type(opt) ~= "table" and type(opt) ~= "userdata" then opt = nil end

local function addOpt(cfg)
	if not opt then return nil end
	return opt:toggle(cfg)
end

if opt then
	opt:toggle({ name = "sub toggle", default = true, flag = "MyFeature_SubA" })
	opt:slider({
		name = "sub value",
		min = 0,
		max = 10,
		default = 3,
		step = 1,
		suffix = "",
		flag = "MyFeature_SubB",
	})
end

-- slider
local speed = right:slider({
	name = "speed",
	min = 0.5,
	max = 10,
	default = 2.5,
	step = 0.1,
	suffix = "x",
	flag = "MySpeed",
	callback = function(v) print("speed =", v) end,
})

-- combo (dropdown — тот же метод)
local mode = right:combo({
	name = "mode",
	list = { "off", "soft", "hard" },
	default = "soft",
	flag = "MyMode",
	callback = function(v) print("mode =", v) end,
})

-- color (callback получает Color3 и прозрачность)
local tint = right:color({
	name = "tint",
	default = Color3.fromRGB(255, 90, 90),
	flag = "MyTint",
	callback = function(c, transparency)
		print("tint =", c, "alpha =", transparency)
	end,
})

-- keybind
local actionKey = right:keybind({
	name = "action key",
	default = "E",
	flag = "MyActionKey",
	callback = function(v) print("action key =", v) end,
})

-- button
left:button({
	name = "run once",
	icon = "play",
	callback = function() toast("Запуск", "кнопка нажата") end,
})

-- label (текст меняется через set)
local stateLabel = left:label({ name = "state: idle", wrap = true })

--------------------------------------------------------------------------
-- 5. GALLERY (сетка иконок/моделей с поиском)
--------------------------------------------------------------------------

local skinGrid = tabExt:gallery({
	name = "skins",
	icon = "shirt",
	side = "right",
	height = 260,
	cell = 78,
	gap = 6,
	multi = true,
	thumb = "Asset", -- "Asset" | "BundleThumbnail"
	search = true,
	tools = true,
	blank = "shirt",
	empty = "ничего не добавлено",
	list = {
		{ name = "default", label = "Default", id = 0 },
	},
	default = "default",
	flag = "MySkins",
	buttons = {
		{
			icon = "plus",
			tip = "добавить по id",
			callback = function()
				if type(lib.ask) ~= "function" then return end
				lib:ask({
					title = "add skin",
					icon = "plus",
					hint = "asset id",
					accept = "add",
					deny = "cancel",
					callback = function(text)
						local id = tonumber(tostring(text):match("%d+"))
						if not id then return end

						local rows = skinGrid:get() or {}
						if type(rows) ~= "table" then rows = {} end
						table.insert(rows, { name = tostring(id), label = tostring(id), id = id })
						skinGrid:setdata(rows)
						skinGrid:refresh()
					end,
				})
			end,
		},
	},
	action = {
		icon = "sliders-horizontal",
		callback = function(name, item, x, y, cell)
			if type(lib.popup) == "function" then
				lib:popup({
					title = name,
					icon = "shirt",
					x = x,
					y = y,
					follow = cell,
					items = {
						{ icon = "check", name = "применить", callback = function() print("apply", name) end },
						{ icon = "copy", name = "скопировать id", callback = function()
							if type(setclipboard) == "function" then setclipboard(tostring((item or {}).id or name)) end
						end },
					},
				})
			end
		end,
	},
	callback = function(v)
		-- single: v = "name"; multi: v = { "name1", "name2" }
		print("skins =", typeof(v) == "table" and table.concat(v, ",") or tostring(v))
	end,
})

-- gallery: setdata / setdefault / set / get / refresh / clear / all / search
skinGrid:setdata({
	{ name = "a", label = "Alpha", id = 1 },
	{ name = "b", label = "Beta", id = 2 },
})
skinGrid:refresh()
skinGrid:setdefault("a")

--------------------------------------------------------------------------
-- 6. 3D-ПРЕДПРОСМОТР (CLONE)
--------------------------------------------------------------------------

local preview = tabExt:clone({
	name = "preview",
	side = "left",
	height = 232,
	zoom = 1.2,
	fov = 40,
	callback = function(model, item)
		print("model:", model and model.Name, "viewport:", item and item.viewport)
	end,
})
-- preview.viewport — Instance внутри окна

--------------------------------------------------------------------------
-- 7. ПОДСТРАНИЦЫ (SUB)
--------------------------------------------------------------------------

if type(tabExt.sub) == "function" then
	local branch = tabExt:sub({ name = "advanced", icon = "folder", tip = "доп. настройки" })
	local adv = branch:section({ name = "advanced", side = "left" })
	adv:toggle({ name = "danger", default = false, flag = "MyDanger" })

	if type(branch.setopen) == "function" then
		pcall(function() branch:setopen(true) end)
	end
end

-- проверка видимости текущей страницы:
local function pageVisible()
	local ok, v = pcall(function() return tabMain.page.Visible end)
	return ok and v or false
end

--------------------------------------------------------------------------
-- 8. СОХРАНЕНИЕ КОНФИГОВ (флаги элементов пишутся сюда)
--------------------------------------------------------------------------

local cfgTab, cfgSec = nil, nil

-- цвета темы
local colorsTab = win:tab({ name = "colors", icon = "palette", tip = "цвета меню" })
colorsTab:color({ name = "accent", key = "accent", side = "left" })
colorsTab:color({ name = "text", key = "text", side = "right" })
colorsTab:color({ name = "panel", key = "panel", side = "left" })
colorsTab:color({ name = "header", key = "head", side = "right" })
colorsTab:color({ name = "sidebar", key = "side", side = "left" })
colorsTab:color({ name = "outline", key = "line", side = "right" })
colorsTab:color({ name = "muted", key = "dim", side = "left" })
colorsTab:color({ name = "network", key = "glow", side = "right" })
colorsTab:color({ name = "background", key = "bg", side = "left" })

-- список конфигов
cfgTab = win:tab({ name = "config", icon = "save", tip = "настройки меню" })
cfgTab:configs({ name = "Configs", side = "left" })
cfgSec = cfgTab:section({ name = "Menu", side = "right" })

-- курсор / звуки / хоткеи / ватермарка
if type(lib.cursorlist) == "table" and #lib.cursorlist > 0 then
	cfgSec:toggle({
		name = "custom cursor",
		default = false,
		flag = "MenuCursor",
		callback = function(v) lib:setcursor(v) end,
	})
	cfgSec:dropdown({
		name = "preset",
		list = lib.cursorlist,
		default = lib.cursorlist[1],
		flag = "MenuCursorStyle",
		callback = function(v) lib:setstyle(v) end,
	})
end

cfgSec:toggle({
	name = "menu sounds",
	default = false,
	flag = "MenuSounds",
	callback = function(v) lib:setsound(v) end,
})

if type(lib.tonelist) == "table" then
	cfgSec:dropdown({
		name = "sound",
		list = lib.tonelist,
		default = "Click",
		flag = "MenuTone",
		callback = function(v) lib:settone(v) end,
	})
end

cfgSec:toggle({
	name = "hotkeys",
	default = true,
	flag = "MenuHotkeys",
	callback = function(v) lib:sethotkeys(v) end,
})

cfgSec:toggle({
	name = "watermark",
	default = true,
	flag = "Watermark",
	callback = function(v) lib:setwatermark(v) end,
})

cfgSec:keybind({
	name = "menu key",
	default = "Insert",
	flag = "MenuKeybind",
	callback = function(v) win:setbind(v) end,
})

--------------------------------------------------------------------------
-- 9. СВОЁ СОСТОЯНИЕ ЧЕРЕЗ hook/unhook (переживает сохранение конфигов)
--------------------------------------------------------------------------

lib:hook("my_app_state", "string", function()
	local ok, encoded = pcall(function()
		return game:GetService("HttpService"):JSONEncode({
			speed = speed:get(),
			mode = mode:get(),
			tint = tostring(tint:get()),
		})
	end)
	return (ok and encoded) or "{}"
end, function(v)
	if type(v) == "string" and v ~= "" then
		pcall(function()
			local d = game:GetService("HttpService"):JSONDecode(v)
			if type(d) == "table" then
				if type(d.speed) == "number" then speed:set(d.speed) end
				if type(d.mode) == "string" then mode:set(d.mode) end
			end
		end)
	elseif type(v) == "table" then
		if type(v.speed) == "number" then speed:set(v.speed) end
		if type(v.mode) == "string" then mode:set(v.mode) end
	end
end)

-- при выгрузке:
-- pcall(function() lib:unhook("my_app_state") end)

--------------------------------------------------------------------------
-- 10. ОБНОВЛЕНИЕ ЭЛЕМЕНТОВ ИЗ КОДА
--------------------------------------------------------------------------

task.spawn(function()
	local tickN = 0
	while pageVisible() do
		tickN = tickN + 1
		stateLabel:set(("state: ticks %d"):format(tickN))
		task.wait(1)
	end
end)

-- programmatic set / get
mode:set("hard")
print("mode now:", mode:get())
feature:set(true)
addOpt({ name = "late added", default = true, flag = "MyLate" })

--------------------------------------------------------------------------
-- 11. ВЫГРУЗКА
--------------------------------------------------------------------------

getgenv().MYUI_UNLOAD = function()
	pcall(function() lib:unhook("my_app_state") end)
	pcall(function() lib:unload() end)
	getgenv().shitaroebet = nil
	getgenv().SHLIB = nil
end
