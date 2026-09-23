package chaossync

// recon.go — лабораторная реализация атаки класса Short (1994) /
// Pérez–Cerdeira (1995): реконструкция динамики по скалярной записи через
// delay-embedding и прогноз на 1 шаг ближайшим соседом (k=1 NN).
//
// Используется ТОЛЬКО в тестах и в tools/chaossync-lab (Э6): измеряем,
// сколько сэмплов окна W нужно стороннему наблюдателю, чтобы модель
// предсказывала следующий сэмпл заметно лучше среднего (NMSE < 0.1),
// — для стационарного и для мутирующего поля.
//
// Арифметика расстояний — целочисленная; float64 появляется только в
// финальной метрике отчёта и на динамику ядра не влияет.

// ReconNMSE — нормированная среднеквадратичная ошибка прогноза на 1 шаг
// по окну квантованных сэмплов y с вложением (dim, lag). Первые 70% окна —
// «атлас» соседей, прогноз проверяется на оставшихся 30%. NMSE ~ 1 —
// прогноз на уровне среднего (реконструкция провалилась); NMSE < 0.1 —
// динамика восстановлена с боевым качеством.
func ReconNMSE(y []uint16, dim, lag int) float64 {
	return ReconNMSEH(y, dim, lag, 1)
}

// ReconNMSEH — то же, но прогноз на h шагов вперёд (атлас хранит будущее
// y[j+span+h]; многошаговый прогноз — то, что реально вскрывает динамику).
func ReconNMSEH(y []uint16, dim, lag, h int) float64 {
	if dim < 1 || lag < 1 || h < 1 {
		return 1
	}
	n := len(y)
	span := (dim - 1) * lag
	m := n - span - h // векторов с известным «следующим» сэмплом
	if m < 64 {
		return 1 // окно слишком мало для вывода — считаем неуспехом
	}
	train := m * 7 / 10
	if train < 16 || m-train < 16 {
		return 1
	}

	// Среднее и знаменатель NMSE по тестовой части.
	var sum, sumsq int64
	var cnt int64
	for i := train; i < m; i++ {
		v := int64(y[i+span])
		sum += v
		sumsq += v * v
		cnt++
	}
	if cnt == 0 {
		return 1
	}
	// var*cnt = sumsq - sum^2/cnt (может быть 0 для константного сигнала).
	denomNum := sumsq*cnt - sum*sum
	if denomNum <= 0 {
		return 1
	}

	var errSum int64
	for i := train; i < m; i++ {
		best := -1
		var bestDist int64 = -1
		for j := 0; j < train; j++ {
			var d int64
			for k := 0; k < dim; k++ {
				diff := int64(y[i+k*lag]) - int64(y[j+k*lag])
				d += diff * diff
			}
			if bestDist < 0 || d < bestDist {
				bestDist = d
				best = j
			}
		}
		pred := int64(y[best+span+h])
		actual := int64(y[i+span+h])
		d := pred - actual
		errSum += d * d
	}
	// NMSE = (errSum/cnt) / (denomNum/cnt^2) = errSum*cnt / denomNum.
	return float64(errSum) * float64(cnt) / float64(denomNum)
}

// ReconMinWindow — минимальное окно W (кратное step), при котором
// ReconNMSE(dim, lag) падает ниже thresh; 0, если до maxW не удалось.
func ReconMinWindow(y []uint16, dim, lag int, thresh float64, startW, step, maxW int) int {
	for w := startW; w <= maxW && w <= len(y); w += step {
		if ReconNMSE(y[:w], dim, lag) < thresh {
			return w
		}
	}
	return 0
}
