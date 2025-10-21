package main

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "image"
    "image/png"
    _ "image/jpeg" // 匿名导入以支持JPEG格式解码
    "io"
    "io/fs"
    "log"
    "math/rand"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    "os"
    "path/filepath"
    "regexp"
    "strconv"
    "strings"
    "time"
)

// --- 图像匹配模块 (四角像素指纹法) ---

// ImageMatcher 使用四角像素指纹法高效管理模板图片并进行匹配。
type ImageMatcher struct {
    templates map[string]image.Image // key: 四角像素指纹
}

// NewImageMatcher 通过加载指定目录下的图片文件来初始化一个新的 ImageMatcher。
func NewImageMatcher(templateDir string) (*ImageMatcher, error) {
    templates := make(map[string]image.Image)
    log.Printf("正在从 '%s' 目录加载模板图片...", templateDir)

    err := filepath.Walk(templateDir, func(path string, info fs.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if !info.IsDir() && (strings.HasSuffix(info.Name(), ".png") || strings.HasSuffix(info.Name(), ".jpg")) {
            file, err := os.Open(path)
            if err != nil {
                log.Printf("[警告] 无法打开模板文件 %s: %v", path, err)
                return nil
            }
            defer file.Close()

            img, _, err := image.Decode(file)
            if err != nil {
                log.Printf("[警告] 无法解码模板图片 %s: %v", path, err)
                return nil
            }

            // 为每个加载的模板图片生成指纹，并存入map。
            fingerprint := generateFingerprint(img)
            if fingerprint != "" {
                templates[fingerprint] = img
                log.Printf("已加载模板: %s (Fingerprint: %s)", info.Name(), fingerprint)
            }
        }
        return nil
    })

    if err != nil {
        return nil, fmt.Errorf("加载模板目录失败: %w", err)
    }
    if len(templates) == 0 {
        return nil, fmt.Errorf("模板目录 '%s' 为空或无法读取", templateDir)
    }

    return &ImageMatcher{templates: templates}, nil
}

// generateFingerprint 提取图片四个角落的像素颜色，生成一个唯一的字符串指纹。
// 这种方法对于背景图与模板图尺寸、主体内容一致，仅缺口不同的场景非常高效。
func generateFingerprint(img image.Image) string {
    bounds := img.Bounds()
    points := []image.Point{
        {X: bounds.Min.X, Y: bounds.Min.Y},
        {X: bounds.Max.X - 1, Y: bounds.Min.Y},
        {X: bounds.Min.X, Y: bounds.Max.Y - 1},
        {X: bounds.Max.X - 1, Y: bounds.Max.Y - 1},
    }

    var parts []string
    for _, p := range points {
        if !(p.In(bounds)) {
            log.Printf("[警告] 指纹采样点 %v 超出图片边界 %v", p, bounds)
            return ""
        }
        r, g, b, _ := img.At(p.X, p.Y).RGBA()
        // RGBA() 返回 16 位颜色值，右移 8 位得到 8 位标准值。
        r8, g8, b8 := uint8(r>>8), uint8(g>>8), uint8(b>>8)
        parts = append(parts, fmt.Sprintf("%d-%d-%d", r8, g8, b8))
    }

    return strings.Join(parts, "_")
}

// findMatchByCorners 根据输入图片的指纹在模板库中查找匹配项。
func (m *ImageMatcher) findMatchByCorners(img image.Image) (image.Image, error) {
    fingerprint := generateFingerprint(img)
    if fingerprint == "" {
        return nil, fmt.Errorf("为当前图片生成指纹失败")
    }
    log.Printf("为当前图片生成指纹: %s", fingerprint)

    template, ok := m.templates[fingerprint]
    if ok {
        log.Println("指纹匹配成功！找到了对应的模板。")
        return template, nil
    }

    return nil, fmt.Errorf("未找到匹配的模板指纹")
}

// findGapByComparison 逐列对比背景图和模板图的像素差异，以定位滑块缺口的左侧边缘。
func findGapByComparison(bgImg, templateImg image.Image) (int, error) {
    bounds := bgImg.Bounds()
    // 扫描范围优化：根据经验，缺口通常不会出现在图片的最左侧。
    scanStartX := 60
    scanEndX := bounds.Max.X - 20

    // 1. 计算每一列的像素差异总和
    diffs := make([]int, bounds.Max.X)
    for x := scanStartX; x < scanEndX; x++ {
        var colDiff int
        for y := 0; y < bounds.Max.Y; y++ {
            r1, g1, b1, _ := bgImg.At(x, y).RGBA()
            r2, g2, b2, _ := templateImg.At(x, y).RGBA()
            // 使用整数运算计算RGB差异，比浮点数转换效率更高。
            diff := abs(int(r1>>8)-int(r2>>8)) + abs(int(g1>>8)-int(g2>>8)) + abs(int(b1>>8)-int(b2>>8))
            colDiff += diff
        }
        diffs[x] = colDiff
    }

    // 2. 找到差异的最大值，用于确定阈值
    maxDiff := 0
    for x := scanStartX; x < scanEndX; x++ {
        if diffs[x] > maxDiff {
            maxDiff = diffs[x]
        }
    }

    // 如果最大差异过小，说明两张图可能完全相同，没有缺口。
    if maxDiff < 10000 { // 此阈值可根据实际情况调整。
        return 0, fmt.Errorf("图片差异过小，可能未找到缺口")
    }

    // 3. 设置动态阈值，通常为最大差异的某个比例，以适应不同图片的差异分布。
    // 比例在 0.3 到 0.5 之间通常效果较好。
    threshold := int(float64(maxDiff) * 0.35)

    // 4. 从左到右遍历，找到第一个差异值超过阈值的x坐标，即为缺口左边缘。
    for x := scanStartX; x < scanEndX; x++ {
        if diffs[x] > threshold {
            log.Printf("找到缺口左边缘: x=%d (差异值=%d, 阈值=%d)", x, diffs[x], threshold)
            return x, nil
        }
    }

    return 0, fmt.Errorf("通过阈值比对未能找到缺口")
}

// abs 返回整数的绝对值。
func abs(n int) int {
    if n < 0 {
        return -n
    }
    return n
}

// --- 核心验证码破解逻辑 ---

// CaptchaSolver 封装了破解验证码所需的全部状态和方法。
type CaptchaSolver struct {
    Client            *http.Client
    BaseURL           string
    UserAgent         string
    InstanceID        string
    Matcher           *ImageMatcher
    initialJSessionID string // 存储首次访问时获取的JSESSIONID，用于最终提交
}

// refreshResponse 定义了刷新验证码接口的JSON响应结构。
type refreshResponse struct {
    Si   string `json:"si"`  // 背景图ID
    Mi   string `json:"mi"`  // 滑块图ID (未使用)
    Imtk string `json:"imtk"` // 图片请求令牌
    T    int64  `json:"t"`   // 时间戳
}

// verifyResponse 定义了提交验证接口的JSON响应结构。
type verifyResponse struct {
    Status  string `json:"status"`
    Message string `json:"message"`
}

// NewCaptchaSolver 创建并初始化一个 CaptchaSolver 实例。
func NewCaptchaSolver(baseURL string, matcher *ImageMatcher) (*CaptchaSolver, error) {
    jar, err := cookiejar.New(nil)
    if err != nil {
        return nil, fmt.Errorf("创建 cookie jar 失败: %w", err)
    }
    client := &http.Client{Jar: jar, Timeout: 20 * time.Second}
    return &CaptchaSolver{
        Client:     client,
        BaseURL:    strings.TrimRight(baseURL, "/"),
        UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        InstanceID: "zfcaptchaLogin",
        Matcher:    matcher,
    }, nil
}

// getInitialSession 访问登录页以获取初始的 JSESSIONID，这是后续所有请求的基础。
func (s *CaptchaSolver) getInitialSession() error {
    reqURL := strings.TrimRight(s.BaseURL, "/") + "/jwglxt/"
    log.Printf("步骤 0: 访问登录页面获取 JSESSIONID: %s", reqURL)

    req, err := http.NewRequest(http.MethodGet, reqURL, nil)
    if err != nil {
        return fmt.Errorf("创建初始请求失败: %w", err)
    }
    if s.UserAgent != "" {
        req.Header.Set("User-Agent", s.UserAgent)
    }

    resp, err := s.Client.Do(req)
    if err != nil {
        return fmt.Errorf("访问登录页面失败: %w", err)
    }
    defer resp.Body.Close()

    // 从最终请求的URL（可能经过重定向）的cookie jar中查找JSESSIONID。
    finalURL := resp.Request.URL
    for _, c := range s.Client.Jar.Cookies(finalURL) {
        if c.Name == "JSESSIONID" {
            s.initialJSessionID = c.Value
            log.Printf("成功获取并存储初始 JSESSIONID: %s", c.Value)
            return nil
        }
    }

    // 作为一个备用方案，也检查原始请求URL的cookie jar。
    if u2, _ := url.Parse(reqURL); u2 != nil {
        for _, c := range s.Client.Jar.Cookies(u2) {
            if c.Name == "JSESSIONID" {
                s.initialJSessionID = c.Value
                log.Printf("成功获取并存储初始 JSESSIONID (备用方案): %s", c.Value)
                return nil
            }
        }
    }

    return fmt.Errorf("未能从登录页面获取 JSESSIONID")
}

// getRTK 从验证码的JavaScript资源文件中解析出rtk令牌。
func (s *CaptchaSolver) getRTK() (string, error) {
    reqURL := fmt.Sprintf("%s/jwglxt/zfcaptchaLogin?type=resource&instanceId=zfcaptchaLogin&name=zfdun_captcha.js", s.BaseURL)
    log.Printf("步骤 1: 从 JS 文件获取 RTK 令牌: %s", reqURL)

    req, _ := http.NewRequest("GET", reqURL, nil)
    req.Header.Set("User-Agent", s.UserAgent)
    resp, err := s.Client.Do(req)
    if err != nil {
        return "", fmt.Errorf("获取 JS 文件失败: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("读取 JS 文件响应体失败: %w", err)
    }

    re := regexp.MustCompile(`rtk:'([a-f0-9\-]+)'`)
    matches := re.FindStringSubmatch(string(body))
    if len(matches) < 2 {
        return "", fmt.Errorf("在 JS 文件中未找到 RTK 令牌")
    }
    rtk := matches[1]
    log.Printf("成功找到 RTK 令牌: %s", rtk)
    return rtk, nil
}

// refreshCaptcha 请求新的验证码图片信息，包括图片ID和令牌。
func (s *CaptchaSolver) refreshCaptcha(rtk string) (*refreshResponse, error) {
    log.Println("步骤 2: 刷新验证码以获取图片信息...")
    params := url.Values{}
    params.Set("type", "refresh")
    params.Set("rtk", rtk)
    params.Set("time", strconv.FormatInt(time.Now().UnixMilli(), 10))
    params.Set("instanceId", s.InstanceID)

    reqURL := fmt.Sprintf("%s/jwglxt/zfcaptchaLogin?%s", s.BaseURL, params.Encode())
    resp, err := s.Client.Get(reqURL)
    if err != nil {
        return nil, fmt.Errorf("验证码刷新请求失败: %w", err)
    }
    defer resp.Body.Close()

    var refreshData refreshResponse
    if err := json.NewDecoder(resp.Body).Decode(&refreshData); err != nil {
        return nil, fmt.Errorf("解析 refresh 响应 JSON 失败: %w", err)
    }
    return &refreshData, nil
}

// downloadImage 根据图片ID和令牌下载验证码图片。
func (s *CaptchaSolver) downloadImage(id, imtk string, t int64) (image.Image, error) {
    params := url.Values{}
    params.Set("type", "image")
    params.Set("id", id)
    params.Set("imtk", imtk)
    params.Set("t", strconv.FormatInt(t, 10))
    params.Set("instanceId", s.InstanceID)

    reqURL := fmt.Sprintf("%s/jwglxt/zfcaptchaLogin?%s", s.BaseURL, params.Encode())
    resp, err := s.Client.Get(reqURL)
    if err != nil {
        return nil, fmt.Errorf("下载图片 %s 失败: %w", id, err)
    }
    defer resp.Body.Close()

    img, _, err := image.Decode(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("解码图片 %s 失败: %w", id, err)
    }
    return img, nil
}

// generateMouseTrack 根据滑块需要移动的距离，生成模拟的鼠标轨迹。
// 轨迹模拟了简单的变速移动和轻微的Y轴抖动，以使其更像人类操作。
func (s *CaptchaSolver) generateMouseTrack(distance int) string {
    type move struct {
        X int `json:"x"`
        Y int `json:"y"`
        T int `json:"t"`
    }
    var track []move
    startX, startY := 630, rand.Intn(10)+480
    startTime := time.Now().UnixMilli()
    track = append(track, move{X: startX, Y: startY, T: int(startTime)})

    totalDuration := int64(rand.Intn(400) + 300) // 总耗时在300-700ms之间
    for i := 1; i <= distance; i += rand.Intn(5) + 5 {
        if i > distance {
            break
        }
        currentTime := startTime + (int64(i) * totalDuration / int64(distance))
        track = append(track, move{X: startX + i, Y: startY + rand.Intn(4) - 2, T: int(currentTime)})
    }
    track = append(track, move{X: startX + distance, Y: startY, T: int(startTime + totalDuration)})

    trackBytes, _ := json.Marshal(track)
    return string(trackBytes)
}

// submitVerification 提交包含鼠标轨迹的验证请求。
func (s *CaptchaSolver) submitVerification(rtk, mt string) error {
    extendData := map[string]string{"appName": "Netscape", "userAgent": s.UserAgent, "appVersion": s.UserAgent}
    extendBytes, _ := json.Marshal(extendData)
    extendB64 := base64.StdEncoding.EncodeToString(extendBytes)
    mtB64 := base64.StdEncoding.EncodeToString([]byte(mt))

    postData := url.Values{}
    postData.Set("type", "verify")
    postData.Set("rtk", rtk)
    postData.Set("time", strconv.FormatInt(time.Now().UnixMilli(), 10))
    postData.Set("mt", mtB64)
    postData.Set("instanceId", s.InstanceID)
    postData.Set("extend", extendB64)

    log.Println("--- [调试] 准备提交验证数据 ---")
    log.Printf("rtk: %s", rtk)
    log.Printf("mt (base64): %s", mtB64)
    log.Printf("extend (base64): %s", extendB64)
    log.Println("--------------------------")

    reqURL := fmt.Sprintf("%s/jwglxt/zfcaptchaLogin", s.BaseURL)
    req, _ := http.NewRequest("POST", reqURL, strings.NewReader(postData.Encode()))
    req.Header.Set("User-Agent", s.UserAgent)
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

    resp, err := s.Client.Do(req)
    if err != nil {
        return fmt.Errorf("验证请求失败: %w", err)
    }
    defer resp.Body.Close()

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("读取验证响应体失败: %w", err)
    }
    log.Printf("--- [调试] 服务器原始响应 ---\n%s\n--------------------------", string(respBody))

    var verifyRes verifyResponse
    if err := json.Unmarshal(respBody, &verifyRes); err != nil {
        return fmt.Errorf("解析验证响应失败: %w", err)
    }
    if verifyRes.Status != "success" {
        return fmt.Errorf("验证码验证失败: %s", verifyRes.Message)
    }
    return nil
}

// Solve 执行完整的验证码破解流程，成功后返回所需的Cookie。
func (s *CaptchaSolver) Solve() (map[string]string, error) {
    if err := s.getInitialSession(); err != nil {
        return nil, err
    }

    rtk, err := s.getRTK()
    if err != nil {
        return nil, err
    }

    refreshData, err := s.refreshCaptcha(rtk)
    if err != nil {
        return nil, err
    }

    log.Println("步骤 3: 下载验证码背景图片...")
    bgImg, err := s.downloadImage(refreshData.Si, refreshData.Imtk, refreshData.T)
    if err != nil {
        return nil, err
    }

    // 将背景图保存到本地，便于调试。
    if file, err := os.Create("debug_bg.png"); err == nil {
        png.Encode(file, bgImg)
        file.Close()
        log.Println("[调试] 背景图片已保存为 debug_bg.png, 请检查。")
    }

    log.Println("步骤 4: 计算滑块距离...")
    if s.Matcher == nil {
        return nil, fmt.Errorf("ImageMatcher 未配置，无法进行验证")
    }

    log.Println("正在使用四角像素指纹匹配法...")
    template, err := s.Matcher.findMatchByCorners(bgImg)
    if err != nil {
        return nil, fmt.Errorf("指纹匹配失败: %w", err)
    }

    distance, err := findGapByComparison(bgImg, template)
    if err != nil {
        return nil, fmt.Errorf("模板比对失败: %w", err)
    }
    log.Printf("计算出的滑块距离为: %d 像素", distance)

    log.Println("步骤 5: 生成鼠标轨迹...")
    mouseTrack := s.generateMouseTrack(distance)

    log.Println("步骤 6: 提交验证请求...")
    if err := s.submitVerification(rtk, mouseTrack); err != nil {
        return nil, err
    }

    log.Println("步骤 7: 提取关键 Cookies...")
    cookies := make(map[string]string)

    if s.initialJSessionID == "" {
        return nil, fmt.Errorf("验证流程看似成功，但初始 JSESSIONID 未被记录")
    }
    cookies["JSESSIONID"] = s.initialJSessionID
    log.Printf("使用初始 JSESSIONID: %s", s.initialJSessionID)

    parsedURL, _ := url.Parse(s.BaseURL)
    routeFound := false
    for _, cookie := range s.Client.Jar.Cookies(parsedURL) {
        if cookie.Name == "route" {
            cookies["route"] = cookie.Value
            routeFound = true
            log.Printf("找到 route Cookie: %s", cookie.Value)
            break
        }
    }

    if !routeFound {
        // 注意：某些情况下验证成功后不一定立即返回 route cookie，
        // 因此这里仅作为警告而非致命错误。
        log.Println("[警告] 验证成功，但未能找到 route cookie")
    }

    return cookies, nil
}

// --- HTTP 服务封装 ---

// globalMatcher 是一个全局的图片匹配器实例，在服务启动时初始化一次以提高效率。
var globalMatcher *ImageMatcher

// writeJSONResponse 辅助函数，用于向客户端写入JSON格式的响应。
func writeJSONResponse(w http.ResponseWriter, statusCode int, payload interface{}) {
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(payload)
}

// solveHandler 处理 /solve 接口的HTTP请求。
func solveHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        writeJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "只允许 GET 方法"})
        return
    }
    baseURL := r.URL.Query().Get("baseUrl")
    if baseURL == "" {
        writeJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "缺少 'baseUrl' 查询参数"})
        return
    }

    log.Printf("收到请求，目标 baseUrl: %s", baseURL)
    solver, err := NewCaptchaSolver(baseURL, globalMatcher)
    if err != nil {
        log.Printf("错误: 创建 Solver 失败 - %v", err)
        writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "创建解决器实例失败"})
        return
    }

    cookies, err := solver.Solve()
    if err != nil {
        log.Printf("错误: 验证码处理失败 - %v", err)
        writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("验证码处理失败: %v", err)})
        return
    }

    log.Printf("成功为 %s 获取 Cookies", baseURL)
    responsePayload := map[string]interface{}{
        "status": "success",
        "data": map[string]string{
            "jsessionid": cookies["JSESSIONID"],
        },
    }
    if route, ok := cookies["route"]; ok {
        responsePayload["data"].(map[string]string)["route"] = route
    }

    writeJSONResponse(w, http.StatusOK, responsePayload)
}

func main() {
    templateDir := "templates"
    var err error
    globalMatcher, err = NewImageMatcher(templateDir)
    if err != nil {
        log.Fatalf("初始化 ImageMatcher 失败: %v. 请确保 '%s' 目录存在且包含模板图片。", err, templateDir)
    }

    const port = "8080"
    http.HandleFunc("/solve", solveHandler)

    log.Printf("服务器启动，监听端口 %s...", port)
    log.Println("访问示例: http://localhost:8080/solve?baseUrl=http://www.gdjw.zjut.edu.cn")

    if err := http.ListenAndServe(":"+port, nil); err != nil {
        log.Fatalf("服务器启动失败: %v", err)
    }
}